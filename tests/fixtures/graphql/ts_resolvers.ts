import { Arg, Authorized, Mutation, Query, Resolver } from "type-graphql";

import { Widget } from "./models";

@Resolver()
export class WidgetResolver {
  @Query(() => [Widget])
  widgets() {
    return [];
  }

  @Authorized(["admin"])
  @Mutation(() => Widget)
  async deleteWidget(@Arg("id") id: string) {
    return null;
  }
}

export const resolvers = {
  Query: {
    publicFeed: () => [],
  },
};
