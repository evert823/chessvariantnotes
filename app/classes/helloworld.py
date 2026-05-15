class HelloWorld:
    def __init__(self, sometext):
        self.message = f"Hello world {sometext}"
        if len(sometext) < 1:
            raise ValueError("text must not be empty")
