import { ActionFunction, LoaderFunction } from "remix";
import { redirect } from "remix";
import { logout } from "~/utils/session.server";

export const action: ActionFunction = ({ request }) => logout(request);

export let loader: LoaderFunction = () => redirect("/");
