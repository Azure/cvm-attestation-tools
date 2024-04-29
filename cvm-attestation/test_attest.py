# test_attest.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import pytest
from click.testing import CliRunner
from attest import main

def test_attest_successfully():

    runner = CliRunner()
    runner.invoke(main, ['--c', 'somefile.json'])
    assert True