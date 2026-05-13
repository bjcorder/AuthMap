export const GET = () => {
  const DELETE = () => prisma.shadow.delete({ where: { id: "nested" } });
  return Response.json({ ok: Boolean(DELETE) });
};
