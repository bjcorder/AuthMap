import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export async function createUser(email: string) {
  return prisma.user.create({
    data: { email },
  });
}

export async function createUsers(emails: string[]) {
  return prisma.user.createMany({
    data: emails.map((email) => ({ email })),
  });
}

export async function disableUser(id: string) {
  return prisma.user.update({
    where: { id },
    data: { disabled: true },
  });
}

export async function disableDormantUsers() {
  return prisma.user.updateMany({
    where: { dormant: true },
    data: { disabled: true },
  });
}

export async function upsertUser(email: string) {
  return prisma.user.upsert({
    where: { email },
    create: { email },
    update: { lastSeenAt: new Date() },
  });
}

export async function deleteUser(id: string) {
  return prisma.user.delete({
    where: { id },
  });
}

export async function deleteSessions(userId: string) {
  return prisma.session.deleteMany({
    where: { userId },
  });
}

export async function rawDeleteSessions(userId: string) {
  return prisma.$executeRawUnsafe(
    "delete from sessions where user_id = $1",
    userId,
  );
}

export async function rawQueryReadOnly() {
  return prisma.$queryRaw`select * from users`;
}
