# test_attest.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import pytest
from click.testing import CliRunner
from attest import attest

def test_attest_successfully():
    runner = CliRunner()
    runner.invoke(attest, ['--c', 'somefile.json'])
    assert True

def test_attest_successfully_with_type_option():
    runner = CliRunner()
    runner.invoke(attest, ['--c', 'somefile.json', '--t', 'Platform'])
    assert True

def test_attest_successfully_with_guest_type_option():
    runner = CliRunner()
    runner.invoke(attest, ['--c', 'somefile.json', '--t', 'Guest'])
    assert True

def test_attest_fails_with_incorrect_type_option():
    runner = CliRunner()
    result = runner.invoke(attest, ['--c', 'somefile.json', '--t', 'Invalid'])
    assert result.exit_code != 0
    assert 'Invalid value for' in result.output


