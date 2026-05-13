function requireAuth() {
  return true;
}

export async function GET() {
  requireAuth();
  return Response.json({ ok: true });
}

export const POST = async () => {
  return prisma.session.create({ data: { active: true } });
};
