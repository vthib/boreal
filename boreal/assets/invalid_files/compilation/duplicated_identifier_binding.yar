rule duplicated_binding {
    condition:
        for any i in (1..5): (
            for any j in (1..8): (
                for any i in (1..2): (
                    i == j
                )
            )
        )
}
