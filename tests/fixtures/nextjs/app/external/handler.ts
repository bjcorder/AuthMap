export async function POST() {
  requireAuth();
  return prisma.external.create({ data: { ok: true } });
}
