import click



class CustomOption(click.Option):
    """This wrapper class helps the `click` library to categorize the CLI options."""

    def __init__(self, *args, **kwargs):
        self.category = kwargs.pop("category", None)
        super().__init__(*args, **kwargs)


class CustomCommand(click.Command):
    """This wrapper class instructs the `click` library to list commands in the order that we define their functions."""

    def list_commands(self, ctx: click.Context) -> list[str]:
        """
        List the commands in the order that we define their functions.

        Args:
            ctx (click.Context): The click context.

        Returns:
            list[str]: The list of commands in the order that we define their functions.

        """
        return list(self.commands)

    def format_options(self, ctx: click.Context, formatter: click.HelpFormatter):
        """Format the options by separating them into categories

        Args:
            ctx (click.Context): The click context.
            formatter (HelpFormatter): Format the text-based help page.
        """
        categories = {}

        for param in self.get_params(ctx):
            if isinstance(param, click.Option):
                cat = getattr(param, "category", "OTHER")
                categories.setdefault(cat, []).append(param)

        for category, params in categories.items():
            with formatter.section(category):
                formatter.write_dl([(p.opts[0], p.help or "") for p in params])
