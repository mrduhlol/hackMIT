import { handle, type Env } from "../../server/api";
export const onRequest: PagesFunction<Env> = (context) =>
  handle(context.request, context.env, context);
