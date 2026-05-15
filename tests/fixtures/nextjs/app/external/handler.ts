export async function POST() {
  requireAuth();
  return prisma.external.create({ data: { ok: true } });
}

function withAuth(handler: Function) {
  return handler;
}

function deleteExternal() {
  return prisma.external.delete({ where: { id: "external_1" } });
}

export const DELETE = withAuth(deleteExternal);
