"""
GraphQLModule — YATA RECON module.
Also carries lightweight gRPC-Web surface-awareness probing — both are
"what's actually behind this modern API surface" checks that recon.py's
generic HTML/JS crawling can't answer on its own.
"""
import json
import re
import time
import urllib.parse

# Apollo/federation directives — their presence in an introspected/SDL
# schema means this isn't a standalone GraphQL API but one subgraph of a
# federated graph, which usually implies internal service-to-service trust
# assumptions (entity resolution, @requires/@provides field composition)
# that are easy to get wrong from a security standpoint.
FEDERATION_DIRECTIVES = ["@key", "@external", "@requires", "@provides", "@extends", "@shareable"]

# gRPC-Web endpoints follow a very distinctive URL shape: /<package>.<Service>/<Method>
GRPC_WEB_PATH_RE = re.compile(r'/([A-Za-z0-9_.]+\.[A-Z][A-Za-z0-9_]*)/([A-Z][A-Za-z0-9_]*)$')

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from recon.modules import BaseModule


class GraphQLModule(BaseModule):
    NAME = "GraphQL Probe"

    def run(self):
        self.ui.section("GraphQL — Introspection & Schema Analysis")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        gql_paths = ["/graphql", "/api/graphql", "/graphiql", "/gql", "/query", "/v1/graphql"]
        s = self._session()
        s.headers.update({"Content-Type": "application/json"})

        found = False
        for path in gql_paths:
            if found:
                break
            url = urllib.parse.urljoin(self.base_url, path)
            try:
                # Check 1: Introspection. NOTE: this previously called
                # Validator.validate_json_schema(), a method that has never
                # existed on core.validator.Validator — every hit raised
                # AttributeError, which the broad except below silently
                # swallowed, so this check has never fired a single finding.
                # Replaced with direct, correct JSON parsing.
                resp = s.post(url, json={"query": "{__schema{types{name}}}"}, timeout=self.timeout)
                if resp.status_code == 200:
                    try:
                        body = resp.json()
                    except ValueError:
                        body = None
                    schema = (body or {}).get("data", {}).get("__schema") if isinstance(body, dict) else None
                    if isinstance(schema, dict) and schema.get("types"):
                        type_names = [t.get("name") for t in schema["types"] if isinstance(t, dict) and t.get("name")]
                        self.db.add(
                            title="GraphQL Introspection Enabled",
                            severity="high", url=url, module=self.NAME,
                            description=(
                                "GraphQL schema introspection is enabled in production, revealing the full "
                                f"API structure: {len(type_names)} type(s) discovered, including "
                                f"{', '.join(type_names[:10])}{'…' if len(type_names) > 10 else ''}."
                            ),
                            remediation="Disable introspection in production. Use query depth limiting and query cost analysis.",
                            cvss="7.5",
                            confidence="CONFIRMED",
                            confidence_score=95,
                            evidence=[f"{len(type_names)} types exposed via introspection"],
                            validation_steps=["status_200", "valid_json", "__schema_types_present"],
                        )
                        self.ui.find("high", "GraphQL Introspection Enabled", url)
                        found = True
                        if url not in self.ctx.setdefault("endpoints", []):
                            self.ctx["endpoints"].append(url)

                # Check 2: Aliased Batching (Query Denial of Service)
                batch_query = "{ " + " ".join([f"q{i}: __typename" for i in range(100)]) + " }"
                resp = s.post(url, json={"query": batch_query}, timeout=self.timeout)
                if resp.status_code == 200:
                    try:
                        body = resp.json()
                    except ValueError:
                        body = None
                    data = (body or {}).get("data") if isinstance(body, dict) else None
                    if isinstance(data, dict) and "q99" in data:
                        self.db.add(
                            title="GraphQL Aliased Query Batching (DoS)",
                            severity="medium", url=url, module=self.NAME,
                            description="GraphQL endpoint allows large aliased queries (100 aliases accepted in one request), which can be abused to bypass rate limits or cause server Denial of Service.",
                            remediation="Implement Query Depth Limiting, Query Cost Analysis, and limit the maximum number of aliases per query.",
                            cvss="5.3",
                            confidence="CONFIRMED",
                            confidence_score=90,
                            validation_steps=["status_200", "valid_json", "all_100_aliases_resolved"],
                        )
                        self.ui.find("medium", "GraphQL Aliased Batching", url)
                        found = True
                        if url not in self.ctx.setdefault("endpoints", []):
                            self.ctx["endpoints"].append(url)

                # Check 3: Array Batching
                array_batch = [{"query": "{__typename}"} for _ in range(10)]
                resp = s.post(url, json=array_batch, timeout=self.timeout)
                if resp.status_code == 200:
                    try:
                        body = resp.json()
                    except ValueError:
                        body = None
                    if (isinstance(body, list) and len(body) >= 2
                            and all(isinstance(item, dict) and "data" in item for item in body)):
                        self.db.add(
                            title="GraphQL Array Batching Enabled",
                            severity="medium", url=url, module=self.NAME,
                            description=f"GraphQL endpoint processed an array of {len(body)} queries in a single request. This allows bypassing standard per-request rate limits for brute force attacks (e.g. against login mutations).",
                            remediation="Disable array-based query batching if not required, or ensure rate limiting applies to the total number of operations, not just HTTP requests.",
                            cvss="5.3",
                            confidence="CONFIRMED",
                            confidence_score=90,
                            validation_steps=["status_200", "valid_json_array", "per_item_data_present"],
                        )
                        self.ui.find("medium", "GraphQL Array Batching", url)
                        found = True
                        if url not in self.ctx.setdefault("endpoints", []):
                            self.ctx["endpoints"].append(url)

                # Check 4: Apollo Federation — a federated subgraph exposes
                # its full internal SDL (including composition directives)
                # via `{ _service { sdl } }`, which most standalone GraphQL
                # servers don't even recognize as a field.
                if self._check_federation(s, url):
                    found = True

                time.sleep(self.delay)
            except Exception:
                continue

        # gRPC-Web awareness — independent of whether a GraphQL endpoint
        # exists at all.
        if self._probe_grpc_web(s):
            found = True

        if not found:
            self.ui.info("No GraphQL endpoint / vulnerabilities found.")

    # ─────────────────────────────────────────────────────────────────────────
    def _check_federation(self, s, url):
        """Apollo/Federation-gateway awareness. `{ _service { sdl } }` is
        the federation-spec introspection query every subgraph implements —
        a hit here reveals the FULL underlying schema (including
        @key/@requires/@provides composition directives) even on a gateway
        that has regular introspection disabled, since gateways often
        forget _service isn't covered by that toggle."""
        try:
            resp = s.post(url, json={"query": "{ _service { sdl } }"}, timeout=self.timeout)
        except Exception:
            return False
        if resp.status_code != 200:
            return False
        try:
            body = resp.json()
        except ValueError:
            return False
        sdl = ((body or {}).get("data") or {}).get("_service", {}).get("sdl") if isinstance(body, dict) else None
        if not sdl or not isinstance(sdl, str):
            return False

        directives_found = sorted({d for d in FEDERATION_DIRECTIVES if d in sdl})
        type_count = len(re.findall(r'\btype\s+\w+', sdl))
        entity_types = re.findall(r'type\s+(\w+)[^{]*@key', sdl)

        self.db.add(
            title="GraphQL Apollo Federation — Subgraph SDL Exposed",
            severity="high" if directives_found else "medium", url=url, module=self.NAME,
            description=(
                f"This endpoint responded to the federation-spec `_service {{ sdl }}` query, "
                f"revealing the full internal subgraph schema ({type_count} type(s)"
                + (f", entity types: {', '.join(entity_types[:10])}" if entity_types else "")
                + f"). This is a SEPARATE code path from standard GraphQL introspection — "
                "it commonly stays enabled even when `__schema` introspection has been "
                "explicitly disabled, since teams forget the federation gateway needs it for "
                "schema composition. Federation directives found: "
                f"{', '.join(directives_found) if directives_found else 'none'}."
            ),
            remediation=(
                "Restrict `_service { sdl }` to internal gateway-to-subgraph traffic only "
                "(network-level isolation or a shared secret header) — never expose it on the "
                "public-facing endpoint, same as you would standard introspection."
            ),
            cvss="6.5" if directives_found else "5.3",
            confidence="CONFIRMED", confidence_score=92,
            validation_steps=["status_200", "valid_json", "_service_sdl_field_present"],
            evidence=[f"SDL length: {len(sdl)} chars", f"Types: {type_count}",
                      f"Federation directives: {', '.join(directives_found) if directives_found else 'none'}"],
        )
        self.ui.find("high" if directives_found else "medium", "GraphQL Federation SDL Exposed", url)
        return True

    def _probe_grpc_web(self, s):
        """
        gRPC-Web surface awareness. Without a .proto definition, we can't
        meaningfully fuzz individual RPCs generically — but we CAN (1) spot
        gRPC-Web endpoints already sitting in ctx['endpoints'] purely from
        their distinctive /<package>.<Service>/<Method> URL shape (recon.py's
        JS mining picks these up as plain paths with no idea what they are),
        and (2) check for the gRPC Server Reflection service, which — like
        GraphQL introspection — lets an attacker enumerate the ENTIRE
        service/method/message surface with zero prior knowledge if left
        enabled in production.
        """
        found = False
        grpc_like = [ep for ep in self.ctx.get("endpoints", []) if GRPC_WEB_PATH_RE.search(ep)]
        if grpc_like:
            self.db.add(
                title="gRPC-Web Endpoint(s) Discovered",
                severity="info", url=grpc_like[0], module=self.NAME,
                description=(
                    f"{len(grpc_like)} URL(s) matching the gRPC-Web path convention "
                    "(/<package>.<Service>/<Method>) were seen during recon. These are worth "
                    "manual review with a gRPC-Web-aware proxy (e.g. grpcurl over a gRPC-Web "
                    "transcoder) — standard HTTP fuzzing tooling generally can't exercise "
                    "Protobuf-encoded request bodies meaningfully without the .proto definitions."
                ),
                remediation="No action required purely for discovery — ensure gRPC-Web methods enforce the same authZ/input-validation as any other API surface.",
                cvss="0.0", confidence="MEDIUM", confidence_score=55,
                validation_steps=["url_shape_matched_grpc_web_convention"],
                evidence=[f"Example: {e}" for e in grpc_like[:5]],
            )
            self.ui.find("info", f"gRPC-Web endpoint(s) discovered ({len(grpc_like)})", grpc_like[0])
            found = True

        reflection_paths = [
            "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
            "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
        ]
        for path in reflection_paths:
            url = urllib.parse.urljoin(self.base_url, path)
            try:
                resp = s.post(url, data=b"", timeout=self.timeout,
                               headers={"Content-Type": "application/grpc-web+proto"})
            except Exception:
                continue
            # A real "not found"/routing-miss on a target with no gRPC-Web
            # gateway at all looks like a generic 404 HTML page; a gRPC-Web
            # gateway that routes this path at all (even to reject the
            # empty body) replies with the grpc-status trailer/header
            # gRPC-Web uses instead of a normal HTTP error body.
            if "grpc-status" in {k.lower() for k in resp.headers.keys()}:
                self.db.add(
                    title="gRPC Server Reflection Enabled",
                    severity="high", url=url, module=self.NAME,
                    description=(
                        "The gRPC Server Reflection service responded, which lets any client "
                        "enumerate the complete service/method/message surface (equivalent to "
                        "GraphQL introspection or an exposed OpenAPI spec) with zero prior "
                        "knowledge of the .proto definitions."
                    ),
                    remediation="Disable server reflection in production deployments — it's a development/debugging aid, not a production feature.",
                    cvss="5.3", confidence="HIGH", confidence_score=75,
                    validation_steps=["grpc_status_header_present_on_reflection_path"],
                    evidence=[f"Response headers included grpc-status for: {path}"],
                )
                self.ui.find("high", "gRPC Server Reflection Enabled", url)
                found = True
            time.sleep(self.delay)

        # Real reflection-based enumeration + fuzzing (optional grpcio +
        # grpcio-reflection + protobuf dependency) — see
        # _try_grpc_reflection_fuzz's docstring for what this adds beyond
        # the HTTP-level awareness checks above.
        if self._try_grpc_reflection_fuzz():
            found = True

        return found

    # ─────────────────────────────────────────────────────────────────────────
    def _try_grpc_reflection_fuzz(self):
        """
        Real gRPC reflection-based service/method enumeration AND fuzzing —
        not just detecting that reflection exists (the HTTP-level check
        above), but actually using it the way an attacker would: connect
        over native gRPC (HTTP/2), ask Server Reflection to list every
        service with zero prior .proto knowledge, fetch each one's real
        FileDescriptorProto, dynamically build live Python message classes
        from it (google.protobuf's DescriptorPool + MessageFactory — no
        generated stub needed), and invoke each discovered method with a
        generic empty/default request.

        Requires the optional grpcio + grpcio-reflection + protobuf
        dependencies — degrades to a no-op when they're not installed, same
        pattern as every other optional-dependency feature here. This only
        ever succeeds against a target that exposes native gRPC directly
        reachable from outside; a target that's gRPC-Web-only behind an
        Envoy-style proxy to an unreachable internal backend is a genuine,
        honest limitation, not a bug — the HTTP-level checks above still
        cover that case as best they can from the outside.
        """
        try:
            import grpc
            from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc
            from google.protobuf import descriptor_pb2, descriptor_pool as _dp_module, message_factory
        except ImportError:
            return False

        host = urllib.parse.urlparse(self.base_url).netloc.split(':')[0]
        # gRPC has no equivalent of an HTTP redirect to tell us the real
        # port — try TLS on the conventional ports first, then plaintext.
        candidates = [(f"{host}:443", True), (f"{host}:50051", False),
                      (f"{host}:8080", False), (f"{host}:9090", False)]

        found = False
        for target, use_tls in candidates:
            if self._probe_grpc_target(target, use_tls, grpc, reflection_pb2, reflection_pb2_grpc,
                                        descriptor_pb2, _dp_module, message_factory):
                found = True
                break  # one live, enumerable target is enough — stop probing further ports
        return found

    def _probe_grpc_target(self, target, use_tls, grpc, reflection_pb2, reflection_pb2_grpc,
                            descriptor_pb2, dp_module, message_factory):
        try:
            if use_tls:
                channel = grpc.secure_channel(target, grpc.ssl_channel_credentials())
            else:
                channel = grpc.insecure_channel(target)
            grpc.channel_ready_future(channel).result(timeout=min(6, self.timeout))
        except Exception:
            return False

        try:
            stub = reflection_pb2_grpc.ServerReflectionStub(channel)
            responses = stub.ServerReflectionInfo(
                iter([reflection_pb2.ServerReflectionRequest(list_services="")]), timeout=self.timeout)
            service_names = [svc.name for resp in responses for svc in resp.list_services_response.service]
        except Exception:
            return False

        if not service_names:
            return False

        self.db.add(
            title="gRPC Server Reflection — Live Service Enumeration Succeeded",
            severity="high", url=f"grpc://{target}", module=self.NAME,
            description=(
                f"Connected directly to {target} over native gRPC and enumerated "
                f"{len(service_names)} service(s) via Server Reflection with zero prior "
                f"knowledge of any .proto definitions: "
                f"{', '.join(service_names[:10])}{'…' if len(service_names) > 10 else ''}. "
                "This is the full attack surface (every service/method/message shape) "
                "exposed with no authentication required just to enumerate it."
            ),
            remediation="Disable gRPC Server Reflection in production deployments.",
            cvss="7.5", confidence="CONFIRMED", confidence_score=98,
            validation_steps=["native_grpc_channel_connected", "reflection_list_services_succeeded"],
            evidence=[f"Target: {target}", f"Services: {service_names[:20]}"],
        )
        self.ui.find("high", f"gRPC reflection — {len(service_names)} service(s) enumerated live", f"grpc://{target}")

        self._fuzz_grpc_services(target, channel, stub, service_names, reflection_pb2,
                                  descriptor_pb2, dp_module, message_factory, grpc)
        return True

    def _fuzz_grpc_services(self, target, channel, stub, service_names, reflection_pb2,
                             descriptor_pb2, dp_module, message_factory, grpc):
        """For each non-reflection service discovered above: fetch its real
        FileDescriptorProto, register it in a fresh DescriptorPool, build a
        default/empty request message per method via MessageFactory (no
        generated stub — the whole point), and invoke it as a generic
        unary-unary call. A method that accepts a fully empty request with
        no auth at all is reported at INFO (not automatically a bug — a lot
        of RPCs are legitimately open — but worth a human's attention)."""
        pool = dp_module.DescriptorPool()
        tested = 0
        for svc_name in service_names:
            if "reflection" in svc_name.lower() or tested >= 5:
                continue
            try:
                file_responses = stub.ServerReflectionInfo(
                    iter([reflection_pb2.ServerReflectionRequest(file_containing_symbol=svc_name)]),
                    timeout=self.timeout)
                for fresp in file_responses:
                    for fd_bytes in fresp.file_descriptor_response.file_descriptor_proto:
                        fdp = descriptor_pb2.FileDescriptorProto()
                        fdp.ParseFromString(fd_bytes)
                        try:
                            pool.Add(fdp)
                        except Exception:
                            pass  # already added, or a dependency-ordering hiccup — best-effort
            except Exception:
                continue

            try:
                svc_desc = pool.FindServiceByName(svc_name)
            except Exception:
                continue

            for method in svc_desc.methods:
                tested += 1
                try:
                    request_cls = message_factory.GetMessageClass(method.input_type)
                    response_cls = message_factory.GetMessageClass(method.output_type)
                    method_path = f"/{svc_name}/{method.name}"
                    call = channel.unary_unary(
                        method_path,
                        request_serializer=lambda msg: msg.SerializeToString(),
                        response_deserializer=response_cls.FromString,
                    )
                    call(request_cls(), timeout=self.timeout)  # zero-valued default — generic, harmless probe
                except grpc.RpcError:
                    continue  # an auth/validation rejection is the normal, healthy outcome
                except Exception:
                    continue

                self.db.add(
                    title=f"gRPC Method Reachable Unauthenticated: {method_path}",
                    severity="info", url=f"grpc://{target}{method_path}", module=self.NAME,
                    description=(
                        f"{method_path} (discovered purely via reflection — never referenced in "
                        "any public API docs) accepted a fully empty/default request with no "
                        "authentication and returned a response. Worth manual review for "
                        "business-logic impact."
                    ),
                    remediation="Confirm this method is intended to be reachable without authentication server-side; add authorization checks if not.",
                    cvss="0.0", confidence="CONFIRMED", confidence_score=80,
                    validation_steps=["method_discovered_via_reflection", "empty_request_invoked_successfully"],
                )
                self.ui.find("info", f"gRPC method reachable — {method_path}", f"grpc://{target}{method_path}")
                time.sleep(self.delay)


# ─── HTTP Smuggling Module ─────────────────────────────────────────────────────