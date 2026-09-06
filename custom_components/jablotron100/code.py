import re


def validate_authorisation_code(code: str) -> str:
	if not isinstance(code, str) or re.fullmatch(r"(?:[0-9]{4,8}|[0-9]{1,3}\*[0-9]{4,6})", code) is None:
		raise ValueError("Invalid authorisation code")
	return code