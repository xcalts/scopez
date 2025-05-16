import click


class OrderCommands(click.Group):
    """It instructs the `click` library to list commands in the order that we define their functions."""

    def list_commands(self, ctx: click.Context) -> list[str]:
        """List the commands in the order that we define their functions.

        Args:
            ctx (click.Context): The click context.

        Returns:
            list[str]: The list of commands in the order that we define their functions.
        """
        return list(self.commands)
