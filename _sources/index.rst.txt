cybersecuritykit: Learn How Cybersecurity Works in Python
=========================================================

.. include:: /_generated/vars.rst

**cybersecuritykit** is a teaching toolkit for cybersecurity, spanning
|num_subpackages| subpackages -- from classical ciphers and block-cipher
cryptanalysis to security protocols, access control, side channels, software
exploitation, intrusion detection, malware epidemics, data privacy and risk --
under one small, typed API. It's built for students working through a course,
curious learners who want to see how an attack actually works, and educators
building a demonstration. Every construction is written out in plain Python on
the standard library, with parameters small enough that each value can be
inspected.

Every subpackage's :doc:`history </history/index>` page traces the
breakthroughs behind it, from al-Kindi's frequency analysis to lattice-based
encryption, and links each one to the code and the gallery experiment that
reproduce it.

.. important::

   This is teaching software, and **everything is simulated**: toy ciphers and
   keys, a toy machine for memory-safety bugs, synthetic packets and logs, and
   epidemic models instead of malware. Nothing in the package opens a socket,
   scans a host, or runs an exploit against a real system. :doc:`/scope` states
   every model boundary. For real systems, use audited libraries and tools.

.. include:: /_generated/grid_hub.rst

**cybersecuritykit** is part of a family of packages that share the same
architecture, API conventions, and history-driven documentation.

Install and try it
------------------

.. code-block:: bash

   pip install cybersecuritykit

``import cybersecuritykit`` loads only the standard library; Matplotlib and
NumPy are installed for each subpackage's plotting helpers in ``visualizers``.
Conventionally imported as ``csk``:

.. code-block:: python

   import cybersecuritykit as csk

.. toctree::
   :maxdepth: 2
   :caption: Subpackages
   :hidden:

   subpackages/index

.. toctree::
   :maxdepth: 2
   :caption: History
   :hidden:

   history/index

.. toctree::
   :maxdepth: 2
   :caption: Examples
   :hidden:

   examples/index

.. toctree::
   :maxdepth: 2
   :caption: Learn
   :hidden:

   tutorials/index
   exercises/index
   scope

.. toctree::
   :maxdepth: 2
   :caption: API
   :hidden:

   api/index

.. rubric:: Related toolkits

Sibling Python toolkits for learning and teaching, built the same way:

- `blockchainkit <https://cpoli.github.io/blockchainkit/>`__ -- cryptography and blockchains
- `chemistrykit <https://cpoli.github.io/chemistrykit/>`__ -- computational chemistry
- `engineeringkit <https://cpoli.github.io/engineeringkit/>`__ -- computational engineering
- `financialkit <https://cpoli.github.io/financialkit/>`__ -- quantitative finance
- `mathematicskit <https://cpoli.github.io/mathematicskit/>`__ -- computational mathematics
- `physicskit <https://cpoli.github.io/physicskit/>`__ -- computational physics
- `tbkit <https://cpoli.github.io/tbkit/>`__ -- tight-binding models, band topology and quantum transport
