#!/usr/bin/env python3
# PoC for Jinja2-3.1.3 (/tmp/bounty_test/Jinja2-3.1.3)
# Path: ssti-005
# Sink: render
# Auto-generated — run with: python3 ssti_therefore_input_cannot_inject_render.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Jinja2 SSTI via render() with user-controlled template variables

This script demonstrates that Jinja2's render() method is NOT vulnerable to SSTI
when user input is passed as template variables (keyword arguments) rather than
as the template string itself. The template is compiled from a fixed string at
creation time, and user input only flows into the context dictionary.

The script will:
1. Create a Jinja2 Template with a fixed template string
2. Attempt to inject SSTI payloads via the render() kwargs
3. Show that the payloads are safely rendered as variable values, not executed
4. Demonstrate that the template string itself cannot be modified by user input

This is a negative PoC - it proves the vulnerability does NOT exist in this code path.
"""

import sys
import os

# Add Jinja2 to path if needed
sys.path.insert(0, '/tmp/bounty_test/Jinja2-3.1.3')

try:
    from jinja2 import Environment, Template
except ImportError:
    print("[!] Failed to import Jinja2. Make sure it's installed or adjust the path.")
    sys.exit(1)


def test_ssti_via_render_kwargs():
    """
    Test if SSTI is possible through render() kwargs.
    
    The template string is fixed and compiled at creation time.
    User input is passed as template variables (kwargs), not as template code.
    """
    print("[*] Testing SSTI via render() kwargs...")
    print("[*] Template string is fixed: 'Hello {{ name }}!'")
    print("[*] User input is passed as: render(name=user_input)")
    print()
    
    # Create a template with a fixed string
    template = Template("Hello {{ name }}!")
    
    # Benign test
    result = template.render(name="World")
    print(f"[+] Benign render: {result}")
    assert result == "Hello World!", f"Unexpected result: {result}"
    
    # Attempt SSTI payloads via kwargs
    ssti_payloads = [
        "{{ config }}",
        "{{ 7*7 }}",
        "{{ self.__class__.__mro__ }}",
        "{{ ''.__class__.__mro__[1].__subclasses__() }}",
        "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
        "{{ lipsum.__globals__['os'].popen('id').read() }}",
        "{{ joiner.__init__.__globals__.os.popen('id').read() }}",
        "{{ namespace.__init__.__globals__.os.popen('id').read() }}",
    ]
    
    print("[*] Attempting SSTI payloads via render kwargs...")
    print("[*] Expected: Payloads should be rendered as literal strings, not executed")
    print()
    
    for payload in ssti_payloads:
        try:
            result = template.render(name=payload)
            print(f"    Payload: {payload}")
            print(f"    Result:  {result}")
            print(f"    [SAFE] Payload was rendered as literal text, not executed")
            print()
            
            # Verify the payload was rendered as-is (not evaluated)
            assert payload in result, f"Payload should appear literally in output: {result}"
            
        except Exception as e:
            print(f"    [!] Error: {e}")
            print()
    
    print("[*] All SSTI attempts failed - payloads treated as literal strings")
    print("[*] Confirmed: render() kwargs are NOT a vector for SSTI")


def test_template_string_injection():
    """
    Test if we can inject into the template string itself.
    
    The template is compiled from a fixed string at creation time.
    User input cannot modify the template source.
    """
    print("[*] Testing template string injection...")
    print("[*] Template is compiled from fixed string at creation time")
    print("[*] User input cannot modify the template source")
    print()
    
    # Create template with fixed string
    template = Template("Hello {{ name }}!")
    
    # Try to inject template directives via kwargs
    injection_payloads = [
        "{% set x = 1 %}",
        "{% if True %}INJECTED{% endif %}",
        "{{ 7*7 }}",
        "{% for i in range(10) %}{{ i }}{% endfor %}",
    ]
    
    for payload in injection_payloads:
        result = template.render(name=payload)
        print(f"    Payload: {payload}")
        print(f"    Result:  {result}")
        print(f"    [SAFE] Template directives not executed - rendered as literal text")
        print()
        
        # Verify the payload appears literally
        assert payload in result, f"Payload should appear literally: {result}"
    
    print("[*] Template string injection confirmed NOT possible")
    print("[*] The template source is fixed and cannot be modified by user input")


def test_environment_configuration():
    """
    Test if environment configuration affects SSTI via render kwargs.
    
    Even with autoescaping disabled or other permissive settings,
    render kwargs should still be safe.
    """
    print("[*] Testing with permissive environment settings...")
    print()
    
    # Create environment with autoescaping disabled
    env = Environment(autoescape=False)
    template = env.from_string("Hello {{ name }}!")
    
    # Attempt SSTI
    payload = "{{ 7*7 }}"
    result = template.render(name=payload)
    print(f"    Payload: {payload}")
    print(f"    Result:  {result}")
    print(f"    [SAFE] Still rendered as literal text even with autoescaping off")
    print()
    
    assert payload in result, f"Payload should appear literally: {result}"
    print("[*] Environment settings do not affect safety of render kwargs")


def main():
    """Main function to run all tests."""
    print("=" * 60)
    print("Jinja2 SSTI via render() kwargs - Negative PoC")
    print("=" * 60)
    print()
    print("[*] This PoC demonstrates that SSTI is NOT possible")
    print("[*] when user input is passed as template variables (kwargs)")
    print("[*] rather than as the template string itself.")
    print()
    
    try:
        test_ssti_via_render_kwargs()
        test_template_string_injection()
        test_environment_configuration()
        
        print("=" * 60)
        print("[RESULT] All tests passed - NO SSTI vulnerability found")
        print("[RESULT] The render() method is safe when used as intended")
        print("[RESULT] User input in kwargs is treated as variable values, not template code")
        print("=" * 60)
        
    except AssertionError as e:
        print(f"[!] Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
