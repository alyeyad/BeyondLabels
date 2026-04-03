#!/usr/bin/env python3
# pylint: disable=C0116,W0613

from os.path import exists

HOOKS_FOLDER = ".git/hooks/"
HOOK = "pre-commit"

def prompt(question, default="yes"):
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("Invalid default answer: '%s'" % default)

    while True:
        print(question + prompt + "\r")
        try:
            choice = input().lower()
            if default is not None and choice == "":
                return valid[default]
            elif choice in valid:
                return valid[choice]
            else:
                print("Please respond with '[y]es' or '[n]o'")
        except KeyboardInterrupt:
            exit("Operation aborted. No files have been changed.")

if exists(HOOKS_FOLDER+HOOK):
    overwrite = prompt("pre-commit hook already exists. Overwrite?", None)
    if overwrite == True:
        try:
            with open(HOOK, 'rb') as src, open(HOOKS_FOLDER+HOOK, 'wb') as dst: dst.write(src.read())
            print(f"{HOOK} inside {HOOKS_FOLDER} was replaced successfully.")
        except:
            print(f"{HOOK} could not be written to {HOOKS_FOLDER}.")
    else:
        print("Operation aborted. No files have been changed.")
else:
    try:
        with open(HOOK, 'rb') as src, open(HOOKS_FOLDER+HOOK, 'wb') as dst: dst.write(src.read())
        print(f"{HOOK} hook was added successfully.")
    except:
            print(f"{HOOK} could not be written to {HOOKS_FOLDER}.")
