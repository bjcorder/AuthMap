import { getRepository, Repository } from "typeorm";

import { Account, Profile, Session, User } from "./models";

// Sequelize
export async function createUser(email: string) {
  return User.create({ email });
}

export async function bulkAdd(emails: string[]) {
  return User.bulkCreate(emails.map((email) => ({ email })));
}

export async function disableUser(id: string) {
  return User.update({ disabled: true }, { where: { id } });
}

export async function removeUser(id: string) {
  return User.destroy({ where: { id } });
}

// Mongoose
export async function touchProfile(id: string) {
  return Profile.findByIdAndUpdate(id, { $set: { seen: true } });
}

export async function dropSession(id: string) {
  return Session.deleteOne({ _id: id });
}

// TypeORM
export async function saveAccount(account: Account) {
  const repo = getRepository(Account);
  return repo.save(account);
}

export async function deleteAccount(repository: Repository<Account>, id: string) {
  return repository.delete(id);
}

// Knex
const db = knex({ client: "pg" });

export async function insertAuditLog(entry: object) {
  return db("audit_logs").insert(entry);
}

export async function updateAccount(id: string) {
  return db.table("accounts").update({ disabled: true }).where({ id });
}

export async function deleteSession(id: string) {
  return db("sessions").where({ id }).transacting(trx).del();
}

export async function upsertPreference(userId: string) {
  return db.table("preferences").upsert({ userId, email: true });
}

// This query-shaped helper is not a Knex instance.
export async function unrelatedInsert() {
  return query("events").insert({ kind: "test" });
}

// Repository-pattern receivers are reported as low-confidence review facts.
export async function saveWithStore(user: User) {
  return userStore.save(user);
}

export async function insertWithDao(order: object) {
  return orderDao.insert(order);
}

export async function persistWithManager(entity: object) {
  return entityManager.persist(entity);
}
