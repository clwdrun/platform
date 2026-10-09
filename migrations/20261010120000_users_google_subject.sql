-- Key users on Google's subject (#9).
--
-- `sub` is Google's stable, never-reused identifier for an account. Email is
-- not: an address can be renamed, and a Workspace admin can delete a user and
-- hand the address to someone else. So sign-in finds a user by `sub` and only
-- stores the email as an attribute. **Never link a sign-in to an existing row
-- by email** — that is the account-takeover a reassigned address enables.
--
-- ROLLBACK PLAN: none required. This migration adds one nullable column and its
-- unique constraint; it rewrites no data. Reverting it is dropping the column,
-- which forgets which Google account each user is (they would be unreachable
-- by sign-in until re-linked) but loses no other data.

alter table users
    add column google_subject text unique
        check (char_length(google_subject) between 1 and 255);
