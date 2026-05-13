function requireUser(handler) {
  return handler;
}

function updateProfile() {
  return prisma.profile.update({ where: { id: "me" }, data: { active: true } });
}

export const PATCH = requireUser(updateProfile);
