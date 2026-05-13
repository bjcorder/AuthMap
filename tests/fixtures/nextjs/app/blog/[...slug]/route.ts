function requirePermission() {
  return true;
}

function withAuth(handler: Function) {
  return handler;
}

export const GET = withAuth(async () => {
  requirePermission();
  return Response.json([]);
});
