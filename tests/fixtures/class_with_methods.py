class Greeter:
    def __init__(self, greeting="Hello"):
        self.greeting = greeting

    def greet(self, name):
        return f"{self.greeting}, {name}!"


class Calculator:
    def add(self, a, b):
        return a + b

    def multiply(self, a, b):
        return a * b
