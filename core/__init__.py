"""Core Engine (Bài tập 3): nạp/parse/index Snort rule và đánh giá event.

Package được chia theo đúng các module của đề bài:

    models.py     - data model (Rule, header/option specs, match result)
    parser.py     - Rule Parser & Validator   (4.2)
    loader.py     - Rule Loader               (4.1)
    indexer.py    - Rule Repository/Indexer   (4.3)
    matcher.py    - Rule Matching Engine      (4.4)
    evaluator.py  - Rule Evaluation Engine    (4.5)
    detection.py  - Detection Event Generator (4.6)

Mọi signature đều được nạp từ file ``.rules`` bên ngoài; không có signature
nào bị hard-code trong source code.
"""
