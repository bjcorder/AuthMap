export function requirePermission(permission: string) {
  return function permissionGuard(req: any, res: any, next: any) {
    if (!req.user?.permissions?.includes(permission)) {
      return res.sendStatus(403);
    }
    next();
  };
}

export function requireTenant(req: any, res: any, next: any) {
  if (req.user?.tenantId !== req.params.tenantId) {
    return res.sendStatus(403);
  }
  next();
}
