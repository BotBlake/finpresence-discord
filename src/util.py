from enum import Enum


class Style(Enum):
    RED: str = "\033[31m"
    GREEN: str = "\033[32m"
    YELLOW: str = "\033[33m"
    BLUE: str = "\033[34m"
    MAGENTA: str = "\033[35m"
    CYAN: str = "\033[36m"
    WHITE: str = "\033[37m"
    BG_RED: str = "\033[41m"
    BG_GREEN: str = "\033[42m"
    BG_YELLOW: str = "\033[43m"
    BG_BLUE: str = "\033[44m"
    BG_MAGENTA: str = "\033[45m"
    BG_CYAN: str = "\033[46m"
    BG_WHITE: str = "\033[47m"
    BG_BLACK: str = "\033[40m"
    RESET: str = "\033[0m"
    BOLD: str = "\033[1m"
    DIM: str = "\033[2m"
    ITALIC: str = "\033[3m"
    UNDERLINE: str = "\033[4m"
    BLINK: str = "\033[5m"
    REVERSE: str = "\033[7m"
    HIDDEN: str = "\033[8m"
    STRIKETHROUGH: str = "\033[9m"


def styled(text: str, styles: list[Style]) -> str:
    # Return a styled string
    style = "".join([x.value for x in styles])
    return f"{style}{text}{Style.RESET.value}"


def confirm(message: str = "Continue", default: bool | None = None) -> bool:
    prompts = {True: "(Y/n)", False: "(y/N)", None: "(y/n)"}
    full_message = f"{message} {prompts[default]}: "

    valid_inputs = {"y": True, "yes": True, "n": False, "no": False}
    if default is not None:
        valid_inputs[""] = default

    while (response := input(full_message).strip().lower()) not in valid_inputs:
        print("Error: invalid input")

    return valid_inputs[response]


def get_input(
    message: str,
    valid_inputs: list,
    default: str | None = None,
    show_default: bool = False,
):
    full_message = f"{message} ({default}): "
    if default is not None:
        valid_inputs.append("")
    while (response := input(full_message).strip().lower()) not in valid_inputs:
        print("Error: invalid input")
    if response == "":
        response = default
    return response
