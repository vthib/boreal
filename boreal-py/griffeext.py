import griffe

logger = griffe.get_logger("plop")


OBJECTS = [
    'boreal.Scanner'
]

class InspectSpecificObjects(griffe.Extension):
    """An extension to inspect just a few specific objects."""

    def on_instance(self, *, obj: griffe.Object, **kwargs) -> None:
        logger.info(f"on obj {obj.path}")
        # if obj.path not in OBJECTS:
        #     return

        try:
            runtime_obj = griffe.dynamic_import(obj.path)
        except ImportError as error:
            logger.warning(f"Could not import {obj.path}: {error}")
            return

        logger.info(f"static docstring: {obj.docstring}, runtime docstring: {runtime_obj.__doc__}")
        if obj.docstring is None and runtime_obj.__doc__ is not None:
            obj.docstring = griffe.Docstring(runtime_obj.__doc__)
