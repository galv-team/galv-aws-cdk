def inject_protected_env(env: dict, protected: dict):
    """
    Inject protected environment variables into an environment dictionary, raising an error if any of the protected
    variables are already set.
    """
    for key, value in protected.items():
        if key in env:
            raise ValueError(f"You cannot specify reserved environment variable '{key}'.")
        env[key] = value
