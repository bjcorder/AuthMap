export async function GET() {
  return Response.json({ ok: true });
}

export const PATCH = async () => {
  return prisma.user.update({ where: { id: "user_1" }, data: { disabled: true } });
};
