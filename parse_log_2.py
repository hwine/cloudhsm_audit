# To add a new cell, type '# %%'
# To add a new markdown cell, type '# %% [markdown]'
# %% [markdown]
# # Overview
#
# This notebook "shows the work" of interpretting "who owns what" in a cloudHSM unit.
# It was originally developed to determine if our prod HSM was impacted by a cloudHSM
# firmware bug fixed in April, but just reported in November 2020. We anticipate
# this notebook to be helpful in future audits as well.
# %% [markdown]
# ## Usage
#
# 1. record a terminal session where you collect data from a cloudHSM unit using the [management utility][mgmt-util]:
#     1. run the "[`listUsers`][listUsers]" command.
#     1. for each "`{user_id}`", run the "[`findAllKeys {user_id} 0`][findAllKeys]" command
# 1. copy/paste that log into a local file. ***NB:*** be sure NOT to save the plain text login password
# 1. update the "`filename`" variable in the next cell with the path to the file. (If you're using vscode, it must be the abspath.)
# 1. run all the cells
# 1. interpret the output
#
# [mgmt-util]: https://docs.google.com/document/d/1tVYApGVvSSyMnBrWBryev6VA_1kHm4l1XRHm9rGSZ24/edit#
# [listUsers]: https://docs.aws.amazon.com/cloudhsm/latest/userguide/cloudhsm_mgmt_util-listUsers.html
# [findAllKeys]: https://docs.aws.amazon.com/cloudhsm/latest/userguide/cloudhsm_mgmt_util-findAllKeys.html

# %%
filename = "/home/hwine/wip/cloudhsm_audit/mgmt_log_1.working"


# %%
# read in the file
with open(filename) as f:
    log_lines = f.readlines()
print(f"Processing {len(log_lines)} lines")


# %%
# utility routines
log_line_index = 0


def reset(to: int = 0) -> None:
    global log_line_index
    log_line_index = to


def skip_to(text):
    global log_line_index
    while text not in log_lines[log_line_index]:
        log_line_index += 1


def get_line() -> str:
    global log_line_index
    line = log_lines[log_line_index]
    log_line_index += 1
    return line


def skip_lines(count: int) -> None:
    global log_line_index
    log_line_index += count


# %%
# data structures
from collections import namedtuple

User = namedtuple("User", "user_id user_type user_name")


# %%
# get user info
reset()
skip_to("Number of users found")
number_of_users = int(get_line().split(":")[1])
print(f"found {number_of_users} users")
skip_lines(2)
users = {}
for i in range(1, number_of_users + 1):
    user_id, user_type, user_name, *_ = get_line().split()
    assert int(user_id) == i
    user = User(user_id, user_type, user_name)
    users[i] = {"user": user}

# remember where we finished
start_of_info = log_line_index


# %%
# grab keys for user

# regex for keys
import re

key_pattern = re.compile(
    r"""
    (?P<id>\d+)  # key id
    (?:\(  # ignore the parens around the optional type
        (?P<type>[os,]+)  # grab the type
    \))?  # optional type string
    ,? # separater
""",
    re.VERBOSE,
)
for i in users.keys():
    reset(start_of_info)
    skip_to(f"findAllKeys {i} 0")
    skip_to("Number of keys found ")
    number_of_keys = int(get_line().split()[-1])
    if number_of_keys:
        skip_lines(1)
        key_line = get_line()
        found_keys = []
        for m in key_pattern.finditer(key_line):
            found_keys.append(m.groupdict())
        assert len(found_keys) == number_of_keys
        users[i]["keys"] = found_keys


# %%

key_by_id = {}


def build_key_by_id() -> None:
    global key_by_id
    for user_id, v in users.items():
        if "keys" not in v:
            print(f"no 'keys' for {user_id}")
            continue
        for key in v["keys"]:
            # ignore public keys (type == None)
            key_type = key["type"]
            if key_type and "o" in key_type:
                if key["id"] in key_by_id:
                    print(f"Error! multiple owners for {key['id']}")
                key_by_id[key["id"]] = v["user"]
            elif not key_type:
                print(f"no type for {key}")


build_key_by_id()


def find_key_owner(id: int) -> User:
    global key_by_id
    try:
        owner = key_by_id[id]
    except KeyError:
        print(f"No one owns key {id}")
        owner = User(-1, "", "<unknown>")
    return owner


# %%
# now have all the data, report out anything we don't expect
# Note that different results are reported if "releng" is considered
# a key owner
include_releng = True
key_owners = [k for k, v in users.items() if v["user"].user_name.startswith("ko")]
if include_releng:
    key_owners.extend(
        [k for k, v in users.items() if v["user"].user_name.startswith("releng")]
    )

# keep track of which keys are owned by wrong party
from collections import defaultdict

mis_owned_keys = defaultdict(list)
for ko in key_owners:
    user_name = users[ko]["user"].user_name
    print(f"Checking {user_name} (id:{ko})")
    # all keys owned, none shared to
    for key in users[ko]["keys"]:
        key_type = key["type"]
        if key_type is None:
            continue
        elif "o" not in key_type:
            print(f"""Error! {user_name} doesn't own {key["id"]}""")
            mis_owned_keys[key["id"]].append({"id": ko, "name": user_name})

print(f"{len(mis_owned_keys)} mis-owned keys")


# %%
# display current owners of mis-matched keys
for k, v in mis_owned_keys.items():
    owner = find_key_owner(k)
    print(f"user {owner.user_id} ({owner.user_name}) owns key {k}")
    print(f"""   should be owned by user {v[0]["id"]} ({v[0]["name"]})""")
    assert len(v) == 1
