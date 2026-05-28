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
