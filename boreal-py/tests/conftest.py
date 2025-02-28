def pytest_collection_modifyitems(config, items):
    def key(item):
        if item.name.startswith("test_run_last"):
            return "zzzzzzzz"
        else:
            return str(item.name)

    # Put the tests named "test_run_last" at the end.
    items.sort(key=key)
