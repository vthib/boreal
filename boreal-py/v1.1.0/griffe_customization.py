import griffe

logger = griffe.get_logger("boreal_customization")

class InspectSpecificObjects(griffe.Extension):
    """An extension to inspect just a few specific objects."""

    def on_instance(self, *, obj: griffe.Object, **kwargs) -> None:
        if obj.path == "boreal.boreal.modules":
            # Do not display the value in the doc: this would be the list
            # of modules compiled in the module used when building this doc.
            obj.value = None

        if obj.is_attribute and obj.path.startswith('boreal.boreal'):
            # Attributes cannot have docstrings so the documentation has to come from
            # the stubfile.
            # Apparently in griffe, `boreal.*` is the data coming from the
            # static analysis (the stubfile), and `boreal.boreal.*` is the
            # data coming from the dynamic analysis (the .so).
            # For attributes, the dynamic analysis seems to use `help(var)`,
            # which means getting the int/str type constructor docstring...
            #
            # For those attributes, we want the docstring from the stubfile
            # and not from the dynamic analysis, so remove the dynamic
            # docstring to prevent it from overriding the static one.
            obj.docstring = None
            return

        try:
            runtime_obj = griffe.dynamic_import(obj.path)
        except ImportError:
            # This can fail for objects declared in the stubfile but that do
            # not exist in the module. This is the case for the TypeAlias objects.
            return

        if obj.docstring is None and runtime_obj.__doc__ is not None:
            # Use the docstring from the module instead of the one from the stubfile.
            obj.docstring = griffe.Docstring(runtime_obj.__doc__, parent=obj, parser="google")
