import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export async function createUser(email: string) {
  return prisma.user.create({
    data: { email },
  });
}

export async function disableUser(id: string) {
  return prisma.user.update({
    where: { id },
    data: { disabled: true },
  });
}

export async function deleteSessions(userId: string) {
  return prisma.session.deleteMany({
    where: { userId },
  });
}
