# -*- coding: utf-8 -*-
"""Hypothesis 1 - Hill-Climb substitution on BIF_REST monoalphabetic."""

import dsl, random
from scorer import Scorer
from oracles import aes_open, sources as get_sources

sc = Scorer()
BIF_REST = "bif_rest"
alpha_letters = list("ABCDEFGHIKLMNOPQRSTUVWXYZ")  # no J - 24 letters


def hill_climb_mono(text_start="bff_reast", alphabet=alpha_letters):
    """Monoalphabetic substitution hill-climber."""

    if not isinstance(alphabet, list) or len(set(alphabet)) != 25:
        raise ValueError("Alphabet must be 25 unique letters")

    text_cand = text_start.lower() + "_" * 80

    best_txt = ""
    best_score = -1e9
    current_text = text_cand

    for iteration in range(5):

        score_curr, pt_cur = sc.score(current_text)
