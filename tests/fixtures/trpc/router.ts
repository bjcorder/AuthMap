import publicProcedure from "./publicProcedure";
import authedProcedure, { authedAdminProcedure } from "./authedProcedure";

export const appRouter = {
  publicInfo: publicProcedure.query(async () => {
    return { ok: true };
  }),
  updateProfile: authedProcedure.mutation(async ({ ctx }) => {
    return ctx.user.id;
  }),
  adminStats: authedAdminProcedure.query(async () => {
    return [];
  }),
};
