import express, { Request, Response } from "express";
import { exec } from "child_process";

export function createApp(): express.Express {
  const app = express();

  app.get("/ping", (req: Request, res: Response) => {
    const host: string = req.query.host as string;
    exec(`ping -n 1 ${host}`, (err: Error | null, stdout: string, stderr: string) => {
      res.send(stdout || stderr || String(err));
    });
  });

  return app;
}

if (require.main === module) {
  const port: number = Number(process.env.PORT) || 3000;
  createApp().listen(port, () => console.log(`listening on ${port}`));
}
