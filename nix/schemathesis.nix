{pkgs}:
with pkgs; let
  click = python313Packages.buildPythonPackage rec {
    pname = "click";
    version = "8.3.0";
    format = "pyproject";
    src = fetchPypi {
      inherit pname version;
      sha256 = "sha256-57gjIiTroW9OvkEMJc7Z94dctfMmP/yTzD6NpwXiKcQ=";
    };
    build-system = with python313Packages; [
      flit-core
    ];
    dependencies = with python313Packages; [
      colorama
    ];
  };

  harfile = python313Packages.buildPythonPackage rec {
    pname = "harfile";
    version = "0.4.0";
    format = "pyproject";
    src = fetchPypi {
      inherit pname version;
      sha256 = "sha256-NOLZ7zQQHXaVZr/6s8Qg4Ud3YXQwi+0aA27Y22AMq94=";
    };
    build-system = with python313Packages; [
      hatchling
    ];
  };

  hypothesis-graphql = python313Packages.buildPythonPackage rec {
    pname = "hypothesis_graphql";
    version = "0.11.1";
    format = "pyproject";
    src = fetchPypi {
      inherit pname version;
      sha256 = "sha256-vUmraASj9Ijsqy45wg26bfwhAVJcZ0L1gxz6nv+VKFo=";
    };
    build-system = with python313Packages; [
      hatchling
    ];
    dependencies = with python313Packages; [
      hypothesis
      graphql-core
    ];
  };

  hypothesis-jsonschema = python313Packages.buildPythonPackage rec {
    pname = "hypothesis-jsonschema";
    version = "0.23.1";
    pyproject = true;
    src = fetchPypi {
      inherit pname version;
      sha256 = "sha256-9KwDICQ0KkFJoQJTmE9aVza4Kz/ir7CIjzg0oxFT8hU=";
    };
    build-system = with python313Packages; [
      setuptools
    ];
    dependencies = with python313Packages; [
      hypothesis
      jsonschema
    ];
  };

  pyrate-limiter = python313Packages.buildPythonPackage rec {
    pname = "pyrate_limiter";
    version = "3.9.0";
    format = "pyproject";
    src = fetchPypi {
      inherit pname version;
      sha256 = "sha256-a4guLHfNoHokHTcwl12upCWDRLOch48d2ISd9z9wsM4=";
    };
    build-system = with python313Packages; [
      poetry-core
    ];
    dependencies = with python313Packages; [
    ];
  };

  starlette-testclient = python313Packages.buildPythonPackage rec {
    pname = "starlette_testclient";
    version = "0.4.1";
    format = "pyproject";
    src = fetchPypi {
      inherit pname version;
      sha256 = "sha256-npk//hL6tFYGEWJXgTmGYSJi/hXBu23J45zGhpOsH8U=";
    };
    build-system = with python313Packages; [
      hatchling
    ];
    dependencies = with python313Packages; [
      requests
      starlette
    ];
  };

  schemathesis = python313Packages.buildPythonApplication rec {
    pname = "schemathesis";
    version = "4.6.1";
    format = "pyproject";
    src = fetchPypi {
      inherit pname version;
      sha256 = "sha256-uUasObEX/IpGr01Wfa9YH6BlTnxzZkBPEo+HJI4RKis=fuzz";
    };
    build-system = with python313Packages; [
      hatchling
    ];
    dependencies = with python313Packages; [
      click
      colorama
      harfile
      httpx
      hypothesis
      hypothesis-graphql
      hypothesis-jsonschema
      jsonschema
      junit-xml
      pyrate-limiter
      pytest-subtests
      pytest
      pyyaml
      requests
      rich
      starlette-testclient
      tenacity
      typing-extensions
      werkzeug
    ];
  };
in
  schemathesis
