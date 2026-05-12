import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export async function createAccount(ownerId: string, name: string) {
  return prisma.account.create({
    data: { ownerId, name },
  });
}

export async function updateAccount(accountId: string, data: Record<string, unknown>) {
  return prisma.account.update({
    where: { id: accountId },
    data,
  });
}

export async function deleteAccount(accountId: string) {
  return prisma.account.delete({
    where: { id: accountId },
  });
}
