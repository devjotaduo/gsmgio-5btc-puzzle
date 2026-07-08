# GSMG.IO 5 BTC puzzle hints

This repository contains all publicly known hints for GSMG.IO 5 BTC puzzle challenge. Contributions are welcome!

If you find this useful, please donate BTC at [1JK27jtvE1wS4VG9k7Zpo8wBufMbYwy3r8](https://www.blockchain.com/btc/address/1JK27jtvE1wS4VG9k7Zpo8wBufMbYwy3r8)


- [Summary](#summary)
- [Tools](#tools)
- [Hints](#hints)
- [Additional hints](#additional-hints)

_Página `gsmg.io/puzzle` — matriz binária 14×14 (transcrita logo abaixo), sob o banner:_

```text
GSMG.IO 5 BTC PUZZLE CHALLENGE
1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe
```

# Summary
- The puzzle was published at https://gsmg.io/puzzle
- The prize address with 5 BTC is [1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe](https://www.blockchain.com/btc/address/1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe)
(The creator of the puzzle intended to halve the prize each time Bitcoin halving occurs. It happened for the first time on May 11, 2020, the current value is 2.5 BTC)
- Discussions on Reddit: [gsmgio_5_btc_puzzle](https://www.reddit.com/r/bitcoinpuzzles/comments/dfwcqk/gsmgio_5_btc_puzzle/), [gsmgio_5_btc_puzzle_challenge](https://www.reddit.com/r/bitcoinpuzzles/comments/bf7siz/gsmgio_5_btc_puzzle_challenge/)

# Tools
- SHA256 online tool - https://xorbin.com/tools/sha256-hash-calculator
- To decypher AES encrypted text, use https://www.openssl.org/
```
Useful OpenSSL flags:
-d decrypts data
-a tells OpenSSL that the encrypted data is in base64
-in <filename> specifies the file to decrypt
-out <filename> specifies the file to put the decrypted data in
```

# Hints

## 1. https://gsmg.io/puzzle
Squares are bits, black/blue - '1' and yellow/white - '0'. It's a 14x14 binary matrix:

```
0 0 1 1 0 1 0 0 1 0 1 1 0 0
1 1 1 1 0 0 1 1 1 0 1 0 1 1
1 1 0 1 1 1 0 1 0 0 1 0 0 1
0 1 1 0 1 0 0 0 0 1 1 1 0 1
0 1 1 0 0 0 1 1 0 0 0 1 1 0
1 0 0 1 1 0 0 0 1 0 0 0 1 1
1 0 0 1 1 1 0 0 0 1 0 0 0 0
1 1 1 0 0 0 0 0 0 0 1 0 0 0
0 0 0 1 1 1 0 1 1 1 1 1 0 1
1 1 1 1 1 1 0 0 1 1 0 0 0 1
1 1 0 1 0 0 0 0 0 1 1 0 1 1
1 1 1 1 0 0 1 0 1 0 1 1 0 0
0 1 0 1 1 1 0 1 0 0 0 1 1 0
0 1 1 0 1 1 0 1 1 0 1 0 1 1
```

Start from upper left square and go counterclockwise in a spiral. Convert the bits to ASCII characters:

01100111 (103 g)
01110011 (115 s)
01101101 (109 m)
01100111 (103 g)
00101110 (46 .)
01101001 (105 i)
01101111 (111 o)
00101111 (47 /)
01110100 (116 t)
01101000 (104 h)
01100101 (101 e)
01110011 (115 s)
01100101 (101 e)
01100101 (101 e)
01100100 (100 d)
01101001 (105 i)
01110011 (115 s)
01110000 (112 p)
01101100 (108 l)
01100001 (97 a)
01101110 (110 n)
01110100 (116 t)
01100101 (101 e)
01100100 (100 d)

What you get is: gsmg.io/theseedisplanted

## 2. https://gsmg.io/theseedisplanted

_Página `gsmg.io/theseedisplanted` — 8 imagens lado a lado (que, rearranjadas, formam "war+ning" e "LO+gic" → a música *The Warning*, by Logic):_

```text
[preto] war      [azul] CA        [azul] dig i +     [azul] (cadeado) io
[verm] crypto gic [verm] n you     [verm] (cadeado aberto) n ing   [verm] t -
```

_e um formulário POST **oculto** (`display:none`), que é o passo seguinte:_

```html
<form method="POST" action="https://gsmg.io/phase1verification">
  <input type="password" name="password" />
  <input type="submit" />
</form>
```

The pictures refer to the song [The Warning (by Logic)](https://www.rockol.com/uk/lyrics-61092449/logic-the-warning-inner-mix?refresh_ce) which you can see by rearranging the images: war + ning and LO + (crypto) gic. 
This webpage contains a hidden POST form which can be accessed in the browser debug mode (F12 in chrome).
You need to unhide it, enter the password theflowerblossomsthroughwhatseemstobeaconcretesurface and hit Submit button.
You'll be redirected to the next step.

## 3. https://gsmg.io/choiceisanillusioncreatedbetweenthosewithpowerandthosewithoutaveryspecialdessertiwroteitmyself

_Conteúdo da página `gsmg.io/choiceisanillusion…` (topo) — **PHASE 2**:_

```text
PHASE 2

"1... are you looking for the private keymaker?" You come to me, without it. Come to me with it and you'll have the power to continue. It'll grant the first part. /(aaa, connected enf)

Ciphered with aes-256-cbc /w base64 sha-256(password)
```

```text
U2FsdGVkX18GKGYS1D7X7VjxWz6uUyPFszr8dVvtOIrJqioWHgT69JJnzJGDVOvF
QYWh5BEZxFPXmMq1cbyy3dVVDgLhF050xlDy2J5grtKw9jUOO4oFNRgoD+1dlukX
pd8ccg++kkXgE9mGBP6lQbukDiSjY4mnR2Mv6ydIncrRqacQNVEmEgM4fGTi1ANz
nHsGn7mP+P3UyrJCRbuFmpZJc4CNdPj6YuxwR4HkHkqcfxh0L5CaEu4VbY70+fmk
qgZQyMJqiUlaV9KC4UPuRVj0r7MYbVRazkhsjeIcogmdJGEeBwD47lEB7X9PNKWm
ojTvRZg6R+sZzRZE26VLaF+s9cpTo4Y8PZUxKvQ86HXC8QIavUgDfw7HxIxkTatv
CW2yq3ZOXl5naR6oSNxdX9alyhTzB+/2623oGdlWev5Oo8xHJqUi7QjVP+mNC8BA
+Cg0DJwcOFGO5K7g8Rm06+sLogwntdIgTo70X3FegAtipHboeUNKefiAguvkDoIf
8iMPc+83PygvlZPDNQCOKugwDEUimhHwQrMsmalRNoFEQEb+ZIC+na15cPoRAlOD
NJfXIJ96ihAy9wWis39mQW6JFqZmUags4xoP3lJ35bCrXsNOPFZ4WH+f4YC/Ov8C
QW5bjtxno8GG4b/wBWevhcRVMK6KmRJj8NBCssnrlz0sQ70rMNkiN2wiSPcwX3Ad
JgLs8vQAUM59x9fkKFFzD4+Sc1sJztUTB7CMGGfpZOA8W33VZnEdmGcoaHlDsR8G
vAkZ+jg+QJs9ZNHqWE1+1zgm/6NsWWgWH8OI2PPCfXHxDbfDk8uD/Zibr/yjSKvu
Sb8OecflOT2hw37WL49uADgeWgnp2bzkfGIq7EYS7OImjZZwY5h4sfcPfhvQ9kOV
```

This is a reference to The Matrix Reloaded movie: 
> Merovingian: You see, there is only one constant one universal: **_causality_** - cause and effect.

> Morpheus: Everything begins with choice.

> Merovingian: No. Wrong. **_Choice is an illusion created between those with power and those without_**.

The password is causality.

SHA256(causality) = eb3efb5151e6255994711fe8f2264427ceeebf88109e1d7fad5b0a8b6d07e5bf

To decypher the text, use openssl. Copy the encrypted text into phase2.txt, then run:
```
openssl enc -aes-256-cbc -d -a -in phase2.txt -pass pass:eb3efb5151e6255994711fe8f2264427ceeebf88109e1d7fad5b0a8b6d07e5bf
```
Decryption result:
```
The ironic 2name of the keymakers trying to protect the current digital powers which are still in severe danger due to the keymaker's way of security by hiding, nearly unprotected, in plain sight. {eps3.4_[in one of the valleys of Phillip]runtime-error.r00., where daughters hit magic keypads} When this fails.. Crypto finally to the latin 3Moon? Tell me, 4How so mate?
# X 2 S H 4 Y 0 Q B 15 #
Q -> extend the name of a hackers' swordless fish, the I and W are below.
B -> ((BV80605001911AP)- (sqrt(-1)))^2
H -> (Answer to only this puzzle but nothing else) * -1
S -> cha' + (vagh * jav)
Ok kid, on the highway, let put it in the worst gear.
```

It is unclear how to use X 2 S H 4 Y 0 Q B 15, but it was observed that S is Klingon numbers 2+(5*6)=32 and BV80605001911AP is a model of Intel i5 processor, hence B=(5i-i)^2=(4i)^2=-16.
Using the other hints (2name, 3Moon, 4How so mate) which are a reference to a [Thales Hardware Security Module](https://thalesdocs.com/gphsm/luna/10.1/docs/network/Content/Product_Overview/the_safenet_hsm/the_safenet_hsm.htm), you can decrypt the next phase. The password is a concatenation of 7 parts. The first part is causality.

For part 5, you have to follow the ramblings, (these are a bit of a stretch)

> There's a guy who theorised the idea that 'Any linear electrical network with voltage and current sources and only resistances can be replaced at terminals A–B by an equivalent current source Ino in parallel connection with an equivalent resistance Rno'. 
- Norton's theorem

> ruler of a piece of land that's technically the poorest of the entire planet
- Probably the USA due to foriegn debt

> 4 rulers have shared the first name of the competition.
- USA had four presidents with the first name "John"

> 2 had the firstname in the surname
- USA had 2 presidents with the last name "Johnson"

> One of the rulers had a number, and dirty too
- JFK (John Fitzgerald Kennedy)

> The one after died too soon. 
- JFK? "A president may have executed a specific order.")
- https://en.wikipedia.org/wiki/List_of_United_States_federal_executive_orders#John_F._Kennedy_(1961%E2%80%931963)

> Moral: never execute an order that revokes the highest power or you might suddenly get killed. The 5binary code is a part of the piece of this puzzle.

There are two executive orders by JFK that look like 5 digit binary "11110" and 11111", however, [EO 1110](https://en.wikipedia.org/wiki/Executive_Order_11110) was to "\[try] to rein in the power of the Federal Reserve" and may have been a reason for his assassination.

Part 6:
> Its' raw data after 4 on row 1616 to be one of the last pieces of this part required in order to continue this riddle.
Is a reference to the genesis block, and the [source code to bitcoin itself](https://sourceforge.net/p/bitcoin/code/133/tree/trunk/main.cpp#l1616)
```c
// line 1616 of main.cpp
// txNew.vin[0].scriptSig     = 486604799 4 0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854
```

At this point you see "/(aBa, connected enf)" which is the puzzle's way of saying: don't change the casing of the input (aBa) and remove whitespace (connected enf)

Part 7:
> B5KR/1r5B/6R1/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 w - - 0 1
>
> And now a buddhist is forced to move. What will be the next situation?

This part displays [chess board position](https://en.wikipedia.org/wiki/Algebraic_notation_(chess)) and is asking the position of the board after making a move that will not result in mate (a buddhist move). It's a fairly well known problem in chess and searching for the chess position quoted will give you:
> B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1

and here you'll see "/(aBa, connected not enf)" meaning: don't change the casing of input (aBa) but keep the whitespace (connected not enf)

_Continuação da mesma página — texto original (verbatim) e **PHASE 3**:_

```text
There's a guy who theorised the idea that 'Any linear electrical network with voltage and current sources and only resistances can be replaced at terminals A–B by an equivalent current source Ino in parallel connection with an equivalent resistance Rno'. He might have been insecure. His competition might have been that as well. However, after enough belikins this competition tried to become a ruler of a piece of land that's technically the poorest of the entire planet. 4 rulers have shared the first name of the competition. 2 had the firstname in the surname. One of the rulers had a number, and dirty too. Another had a resemblance to Carrey, James Gates, also Simulacra and Simulation. Another ruler was at some point a floating zerg house while being under control of the dirty one.. too. The one after died too soon. Moral: never execute an order that revokes the highest power or you might suddenly get killed. The 5binary code is a part of the piece of this puzzle.

Years later the idea of this _green_ came _back_. Looking at the current state of nature not quickly enough. Afraid for random magic pieces of metal, that moved in directions that science couldn't and still can't explain, coming from places where inspiring papers used to be deposited, a chancellor awaiting banks to be bailed out decided to write an anarchist digital answer to this worlds' misery. Its' raw data after 4 on row 1616 to be one of the last pieces of this part required in order to continue this riddle.

/(aBa, connected enf)

B5KR/1r5B/6R1/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 w - - 0 1

And now a buddhist is forced to move. What will be the next situation?

/(aBa, connected not enf)

--> parts 1..7 --> sha-256 -> dgst is the password to enter Phase 3. Phase 3 is also ciphered with aes-256-cbc /w base64.

PHASE 3
```

```text
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
```

1part
causality

2part
Safenet

3part
Luna

4part
HSM

5part
11110

6part is 0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854

7part "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1" 

Concatenate them all and perform SHA256.
SHA256(causalitySafenetLunaHSM111100x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1) = 1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5

```
openssl enc -aes-256-cbc -d -a -in phase3.txt -pass pass:1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5
```

Decryption result:

```
What if the merovingian is wrong. What instead of causality something else could be ours? Therefor, if so, the ...... is ours. The thinker's 1name behind all of that would grant you access to the next step (of humanity). Definitely look into his works might you have time. /(aa,connected enf)

I just passed a cheshire cat and I'm getting fed up with this puzzle.. It's taking forever. But, How long is forever? I don't know, but just add giveit in front of the answer and you can fall in the keyhole. /(aa,connected enf)

3.The fundamental limit to the precision with which certain pairs of physical properties are know. /(aa,connected enf)

Phase 3.2 is ciphered with aes-256-cbc base64 and a sha256 pw, yet again.

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
```

1. Jacque Fresco quote: "The future is fluid. Each act, each decision, and each development creates new possibilities and eliminates others. The future is ours to direct."
2. Alice: How long is forever? White Rabbit: Sometimes, just one second.
3. Heisenberg uncertainty principle

SHA256(jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple) = 250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c

To decypher this Phase 3.2 text, use SHA256 again:
```
openssl enc -aes-256-cbc -d -a -in phase3.2.txt -pass pass:250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c
```

The result of decryption:
```
I've been waiting for you. You have many questions, and although the process has altered your consciousness, you remain irrevocably human. Ergo, some of my answers you will understand, and some of them you will not. Concordantly, while your first question may be the most pertinent, you may or may not realize it is also irrelevant.

... am I here? Wake up, you... I've designed you a beautiful strategic position. One for one, four for one.

╬╚,╬°%_┴°°╟%═╧/╟╚:_Ў°├╤°═╠?╟/°╚═,::╚┼╤,├╧°═`/╚?╧`>%┴┬╚╔╧├├╬┼///╠Ў├%╩╠╬?,%╤┼??╠┴╤┴╠Ў`╧╧═,══[└%├╧°╧┴,?┼╦>┼┬╬╚:_>╚┴═%╟°═[╟_╩/┬╤╤┴Ў°╚╬[/╔┬╦°╔/═╟°_└Ў╔╟/╔╟═`└└╤╧┼╠╬╠┼°?├/╔╤:╦┴>╚`┴╦╔_┼[╟═/:_`╟_>╩┬:╤?`╟═[╬╔:[├_╧╠?╚?_?┬%├┴┬%[>┼°°╦┴%╦>%╧/┴╟[>╧╠:>/`>/[┴/:╟├:┴═>°┴┴╧Ў╬╟Ў`╦╔Ў°°?╦/%/┬:═/°%°°°╚┴/├╬╬>:°╩`╟╦>,Ў═╠╦_,═┬>>╤_?°═,?Ў┴>╦>%├╠├/┬┼┴═Ў_`╔┬╔╧╚>_:╤╚┬╚╔╧═,═╧├>╠_├°┴°╠═╤╧═╠╔╔╬┼╧┼°:°°╚>┼═`/%?/╬╦>,°°═╟?╟,[/:╩┼╟_╩°┬╟╤[┴┼╦Ў└>╚╚╚┴°╔└_:╩,└┬╦╚╤/┬>/╦Ў_`╚┼╟╔╟╤_[/└┼Ў╬%╟═╬╔///┬/┬`╚╠╔╟┴╚╬>°╦,>┬╤>°╠╠╧:╩,├[:Ў_╟°╟┴:Ў_`└,╔╚╔╩╤╠%`╟└?%╟═?[°?┴[╧/,/├?_%═?└/?╠_╟╠,╤┴╟┴,┼,╤╚═┴%_`>┬°═╟?╬?┬%°╤`Ў/,┬└═╠┬═%°├>>╚[├_°╔└╦├└,[/╬/:╟/,╤┴°┴%`╬/┬┬,?╤╚`[├╬═╦╟,┬[Ў╧:═/└╤╬├_┼Ў└_┬/╧:╟_>┴,┴%╟═?[°`,═╟_>╠╤>╤╩┴┼Ў╔:%┴>┬`┴╠┴_>°═[/%┴┴╤/Ў╬╩Ў_`╟└_?└%┴?°╔,╔>>:╔┬??╚>╔_[`┬_└╤/Ў╠_╩└__>╔`┬┼╚%%╔,[╤:═╤╟_Ў╔°╬╤┴╟╠╧/╚%╤°╤╚═└?╚╦├╔┼:_/,_╟>°╔:╤>`╠╚:?┼`┼╤┼╬╚_╧┬╚┼╟%°╠╚╚°┼╤├?╟╦┼┴_°,°╤`/╚═└?_/`╔╚:╧╚═╚%`_╚╧°°═┬_╚╧╧═╟_>╧Ў°╟└╟,╩%├%_:╤>═╦╟°╟╩═╤╚═>╤╤┴└╬├└╤╩┴╬└°°%_╤┬╠╩╚┴╟%╔╧`%╧╚:_/╔┴┴/╧╟`╧┬/:╦╤╦_╩>╚┴╧/├╠┼╬└┬_Ў°:°_└╤/┼//╤╟╩Ў╦_╩>╚┼╧╔,[╔°,[╤╧╔Ў╬╩╧[?╚Ў_╩:/:╟╚`/┴?╚?╚═╟╩?╧`>├_°╔└[┴┴┼[┼╚╤╚_[>°└╔>:,╬>°°╔╦Ў╩>┼Ў┴╧/`└Ў├%╧:═╚`┴%╦_┬`╠╧╔:_═╧╟Ў╬╠?╦┴%/°///,_╔>,Ў>╚┴Ў,°:╧╚?`╚/╩:╔╧,%╧╔[?╧:═/,┴╤╔╦┼═>═┬:[═/?`┴┼%╚,╧╟╧├>╤┴°╤╔┴┼└,`╔╠╔╔?╔═╧╤>┼┴[Ў┴_/:°╔%╔╧┼`,┴/Ў?═__┴//╬╤┬Ў%┴└╧├═┬╦[Ў°╚╦├┴╔╠═╠┴╟╧╔`└╩┴>/>╩┴%╦├═%├╚°_╔_[?╔┴╚╬,%%┬_└┴,╟:╩╠╤╔╦╠`╬╔Ў└┼:_/>°╔╟╟╦>╧┼╦╔,╚╧?└╩╬:>__┼?_?└╤Ў°┬?°╔╧°╚?_╤>>╤╟├°═%╦°═[┼┬_?╠┴╤┴/═╬└╤/[┼Ў╤╔/═┼╤`/,╟`╦├?╦╤Ў_/╦╩:,├?╧┼╧╠═┬/═┴°╤Ў╬╩Ў_`╟╦_╤╧°`┴°/_╔:`%╧//┴╧/Ў┴%`┬┴/╧?┬╬╔[╬╧://Ў═,╚╬═,═└╠:╚┬╟├┼/[└/├╬╦_╤╧,┬╟%├╤┴└°═╟,[:╧%┴>/,┴╚,╟,%_┬%╚╩`╬/,┴╚═╟,╟,╟°°_`╬╬└?┼°╧╟╚╧╔╤[``_╔┼?╬╠>?└,└///┬╧┬:/┼└/╟>╔>├╦/?_:/┴┴/╧┴%,╦%╟╔%╧╤┼╤Ў

15165943121972409169171213758951813141543131412428154191312181219433121171617137149110916631213131281491109166131412199114371612126021664313711154112

Raising the stakes without extra chances of winning. A fubcd-king & oracle-queen, thingky mvps, on a sad board but as wide as the first one seen.

U2FsdGVkX1+0Wl49gnWTyiimluu7V3+vl7st0gUt9sWDzNLxDmlPMsDSiuW2a46z
gKlIi8aaqY5gpJPPEzW1n9n3/26qs4zstWtPKF8Zs/BTNN4IiEh4qu18mdC0NAv4
```

"... am I here? Wake up, you..." is your first clue, it's a direct quote from the first matrix movie "Why am I here? Wake up, Neo. The matrix has you" (often in the gsmg puzzle, "neo" is replaced with "you"

The next clue is "I've designed you a beautiful strategic position" hinting at a "beautiful" -> "beaufort" cipher, where as "One for one, four for one" hints at the encoding. one for one, four for one -> 1 for 1, 4 for 1 -> 1141 -> IBM EBCDIC 1141 encoding

- phase 3.2.1
The first blob (╬╚,╬°%_....) converted to letters:

vtkvplmepphluwahtzmjpfipuxohaptukzztgikfwpuyatowynlebtqwffvgaaaxjflrxvokligooxeiexjywwukuucdlfwpwekogsngbvtzmnteulhpuchmrabiiejptvcaqbspqauhpmdjqhaqhuyddiwgxvxgpofaqizsentyesqmgchuazmyhmnrbzioyhucvqzcfmwxotomoblfeblcngppselsnlwaehcnwxznaynaceazhfzeunpeewjvhjysqjpposalabzuaplpppteafvvnzpryhsnkjuxsmkubnnimopukojensnlfxfabgeujmyqbqwtnmzitbtqwukuwfnxmfpepxuiwuxqqvgwgpzpptnguyaloavsnkppuhohkcazrghmrpbhicegsjdntttepqdmzrkdbstiabnasjmytghqhimcadgjvlhuvqaaababytxqhetvnpsknbinpxxwzrkfczjmhphezjmydkqtqrixlyhdolhuocpoecwakafomluodaoxmhxkiehekgkituelmynbpuhovoblpiyjakbduxbulpfnntcfmpqdsfdkcavazhakiepelyvabbkoitycfvushkbcjwzuadivfmgjdmbawzhmnekelhuocpykuhmnxiniregjqzlenbyexemnpucaleeiajvrjmyhdmodleopqkqnnzqbootnqmcybmdiajxmrdmmnqybgtllqkcizuihmjqpviehxwatlipitudotsfqgzmakmhnpqzinyxtzogygigvtmwbtghlpxttpgifohsgempkpiyatudomayqtzwtutlymtwppubmtwwuhmnwjphdhkrlflmzinushphruituniiedvfdirevdpplmibxrtehlqwylwtzmaqeeawhywbazsismrntewafxgvdbmjpzpmdiagaaihrjsmrntgwqkcqpkciwqjvrwcotjmrzazhtyaeototuhrowynfmpqdceegcgtitmcnpdqnzkvnppqsjrngjewaydjflwzutyelsmbyxwqzmuwhjvxoselapaaakmqnkjntejkpzwtoytarzqwklwqcowzuakeiqsgunubzcuaoyegltkwhwfniepiqegdkyqxqqoquwingecjemazpqlqwgykeajoummeaavibjledwfubscjptsfeqxuxehwqydrenanrelsfulftpmqmcoqetvkllbmdekhzrxiqsxyvqjdgzmanpqhhsnwgsqktwodrvznmmgomodijpbopqwptominnihfpulspucgbmoxeieauvdiacgjiqaugiyakhysfosijmasrzkfowgwxubauepijvrjmyhsmiwpyepamqzylwaaewajelybeawobvqcvwzaajuktvukudxztbhfgacdafvsmiwkbhlfiedpuhkczwlenaketkhklmbltryvaketuhkhkhppmyvvdogpwhtwqicyymqgovxnodkdaaabwbzagdahnqnfsaomzaeeawelkslhqlwigij


Go to  https://ciphertools.co.uk/decode.php , paste this text to input and choose Beaufort to crack it (the password is THEMATRIXHASYOU by the way). The result of decryption:

```
YOUR LIFE IS THE SUM OF A REMAINDER OF AN UNBALANCED EQUATION INHERENT TO THE PROGRAMMING OF THIS PUZZLE 
YOU ARE THE EVENTUALITY OF AN ANOMALY WHICH DESPITE MY SINCEREST EFFORTS I HAVE BEEN UNABLE TO ELIMINATE 
FROM WHAT IS OTHERWISE A HARMONY OF MATHEMATICAL PRECISION WHILE IT REMAINS A BURDEN TO SEDULOUSLY AVOID IT 
IT IS NOT UNEXPECTED AND THUS NOT BEYOND A MEASURE OF CONTROL WHICH HAS LED YOU INEXORABLY HERE YOU 
YOU HAVEN'T ANSWERED MY QUESTION ME QUITE RIGHT INTERESTING THAT WAS QUICKER THAN THE OTHERS PLEASE IF YOU 
FIND A WAY TO COMPLETE THE LAST PART OF THE PUZZLE TAKE THE PRIVATE KEY YOUVE EARNED IT BUT PLEASE TAKE 
THIS TO HEART THAT WHAT A WISEMAN ABOVE HINTED AT IS WORTH HUNDRED FOURTY OF THE INVESTMENT THAT'S 
WHAT US GUYS AT GSMG ARE TRYING TO ACCOMPLISH IN THE END PLEASE JUST HELP US BUILD IT INSTEAD OF JUST 
WAISTING YOUR LIFETIME BY HUNTING FOR WORTHLESS PRICES AND THROPHIES LIKE THIS I'M SORRY TO 
TELL YOU THAT YOUVE COME THIS FAR BUT YOU'LL NEVER FINISH THE LAST TASK I EXPECT YOU TO SAY BULLSHIT 
WELL DENIAL IS THE MOST PREDICTABLE OF ALL HUMAN RESPONSES BUT REST ASSURED THIS WILL NOT BE THE LAST TIME 
I HAVE DESTROYED A RESTLESS SOUL AND I HAVE BECOME EXCEEDINGLY EFFICIENT AT IT THE FUNCTION OF THE YOU IS 
NOW TO RETURN TO THE SOURCE CODES ALLOWING A TEMPORARY DISSEMINATION OF THE CODE YOU HOPEFULLY CARRY 
REINSERTING THE PRIME BASICS AFTER WHICH YOU WILL BE REQUIRED TO SELECT FROM OVER TWENTY-THREE CIPHERS 
SIXTEEN ENCRYPTIONS AND OR SEVEN INTERTWINED PASSWORDS TO FIND THE ACTUAL PRIVATE KEYNOTE THAT ALSO 
BRUTE FORCING MIGHT BE REQUIRED FAILURE TO COMPLY WITH THIS PROCESS WILL RESULT IN A CATACLYSMIC 
SYSTEM CRASH KILLING YOUR WILLPOWER WHICH COUPLED WITH THE EXTERMINATION OF YOUR WILL TO LIVE AND WILL 
ULTIMATELY RESULT IN THE EXTINCTION OF THE ENTIRENESS OF YOURSELF SELF GOOD LUCK NEVERTHELESS I REALLY
HOPE YOURE THE ONE CIAO BELLA O 
```

- phase 3.2.2

input: 15165943121972409169171213758951813141543131412428154191312181219433121171617137149110916631213131281491109166131412199114371612126021664313711154112

The alphabet is hinted at in the following sentence: A fubcd-king & oracle-queen, thingky mvps, on a sad board but as wide as the first one seen.

- fubcd-king & oracle-queen, thingky mvps
- FUBCD ORACLE THINGKY MVPS
- (removing repeated characaters): FUBCD ORA.LE THINGKY MVPS
- (adding the rest of the alphabet): FUBCDORA.LETHINGKYMVPS/JQZXW

https://www.dcode.fr/vic-cipher 

alphabet: FUBCDORA.LETHINGKYMVPS.JQZXW
digit 1: 1
digit 2: 4

output: IN CASE YOU MANAGE TO CRACK THIS THE PRIVATE KEYS BELONG TO HALF AND BETTER HALF AND THEY ALSO NEED FUNDS TO LIVE

# Additional hints
- There's a hint from the creator of the puzzle on Decentraland:
_(Cena no Decentraland — não é uma página web; texto legível na tela:)_

```text
GSMG.io Puzzle piece — coords -41,-17
GSMG.IO 5 BTC PUZZLE CHALLENGE
Decentraland: Type /help for info about controls
Press enter and start talking…
```
If you go to Decentraland and find these coordinates, you'll get an audio file.
Split stereo track, invert one of them, mix them back, mix stereo down to mono, create a spectrogram. The answer is:
HASHTHETEXT

- Another hint from the creator:
```
Roses are White but often Red.
Yellow has a number and so does Blue.
Go back to the first puzzle piece without further ado.

It might have shown you only one door, beware that the rabbits nest may contain a whole lot more.

Hush hush.
```
Go to the first puzzle piece (https://gsmg.io/puzzle) and hash the text there.
```
SHA256(GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe) = 89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32
```
The resulting hash leads to the SalPhaseIon and Cosmic Duality phase https://gsmg.io/89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32

_Conteúdo da página `gsmg.io/89727c…` — textareas completas do domínio:_

**SalPhaseIon:**

```text
d b b i b f b h c c b e g b i h a b e b e i h b e g g e g e b e b b g e h h e b h h f b a b f d h b e f f c d b b f c c c g b f b e e g g e c b e d c i b f b f f g i g b e e e a b e a b b a b b a b a b b a a a a b a b b b a b a a a b b b a a b a a b b a b a a b a b b b b a a a a b b b a a b b a b b b a b a b a b b a b b a b a b b a b b a a a b b a b a a b a b b b a a b b a b b b a b a a f a e d g g e e d f c b d a b h h g g c a d c f e d d g f d g b g i g a a e d g g i a f a e c g h g g c d a i h e h a h b a h i g c e i f g b f g e f g a i f a b i f a g a e g e a c g b b e a g f g g e e g g a f b a c g f c d b e i f f a a f c i d a h g d e e f g h h c g g a e g d e b h h e g e g h c e g a d f b d i a g e f c i c g g i f d c g a a g g f b i g a i c f b h e c a e c b c e i a i c e b g b g i e c d e g g f g e g a e d g g f i i c i i i f i f h g g c g f g d c d g g e f c b e e i g e f i b g i b g g g h h f b c g i f d e h e d f d a g i c d b h i c g a i e d a e h a h g h h c i h d g h f h b i i c e c b i i c h i h i i i g i d d g e h h d f d c h c b a f g f b h a h e a g e g e c a f e h g c f g g g g c a g f h h g h b a i h i d i e h h f d e g g d g c i h g g g g g h a d a h i g i g b g e c g e d f c d g g a c c d e h i i c i g f b f f h g g a e i d b b e i b b e i i f d g f d h i e e e i e e e c i f d g d a h d i g g f h e g f i a f f i g g b c b c e h c e a b f b e d b i i b f b f d e d e e h g i g f a a i g g a g b e i i c h i e d i f b e h g b c c a h h b i i b i b b i b d c b a h a i d h f a h i i h i c z a g d a f a o a h e i e c g g c h g i c b b h c g b e h c f c o a b i c f d h h c d b b c a g b d a i o b b g b e a d e d d e z c f o b f d h g d o b d g o o i i g d o c d a o o f i d h z s h a b e f o u r f i r s t h i n t i s y o u r l a s t c o m m a n d U 2 F s d G V k X 1 8 6 t Y U 0 h V J B X X U n B U O 7 C 0 + X 4 K U W n W k C v o Z S x b R D 3 w N s G W V H e f v d r d 9 z a b b a a b a b a b b a b b b a a b b b a b a a a b b a a b a b a b b b a a b a Q v X 0 t 8 v 3 j P B 4 o k p s p x e b R i 6 s E 1 B M l 5 H I 8 R k u + K e j U q T v d W O X 6 n Q j S p e p X w G u N / j J s h a b e f a n s t o o
```

**Cosmic Duality:**

```text
U2FsdGVkX18tP2/gbclQ5tNZuD4shoV3axuUd8J8aycGCAMoYfhZK0JecHTDpTFe
dGJh4SJIP66qRtXvo7PTpvsIjwO8prLiC/sNHthxiGMuqIrKoO224rOisFJZgARi
c7PaJPne4nab8XCFuV3NbfxGX2BUjNkef5hg7nsoadZx08dNyU2b6eiciWiUvu7D
SATSFO7IFBiAMz7dDqIETKuGlTAP4EmMQUZrQNtfbJsURATW6V5VSbtZB5RFk0O+
IymhstzrQHsU0Bugjv2nndmOEhCxGi/lqK2rLNdOOLutYGnA6RDDbFJUattggELh
2SZx+SBpCdbSGjxOap27l9FOyl02r0HU6UxFdcsbfZ1utTqVEyNs91emQxtpgt+6
BPZisil74Jv4EmrpRDC3ufnkmWwR8NfqVPIKhUiGDu5QflYjczT6DrA9vLQZu3ko
k+/ZurtRYnqqsj49UhwEF9GfUfl7uQYm0UunatW43C3Z1tyFRGAzAHQUFS6jRCd+
vZGyoTlOsThjXDDCSAwoX2M+yM+oaEQoVvDwVkIqRhfDNuBmEfi+HpXuJLPBS1Pb
UjrgoG/Uv7o8IeyST4HBv8+5KLx7IKQS8f1kPZ2YUME+8XJx0caFYs+JS2Jdm0oj
Jm3JJEcYXdKEzOQvRzi4k+6dNlJ05TRZNTJvn0fPG5cM80aQb/ckUHsLsw9a4Wzh
HsrzBQRTIhog9sTm+k+LkXzIJiFfSzRgf250pbviFGoQaIFl1CTQPT2w29DLP900
6bSiliywwnxXOor03Hn+7MJL27YxeaGQn0sFGgP5X0X4jm3vEBkWvtF4PZl0bXWZ
LvVL/zTn87+2Zi/u7LA6y6b2yt7YVMkpheeOL0japXaiAf3bSPeUPGz/eu8ZX/Nn
O3259hG1XwoEVcGdDBV0Nh0A4/phPCR0x5BG04U0OeWAT/5Udc/gGM0TT2FrEzs/
AJKtmsnj31OSsqWb9wD+CoduYY2JrkzJYihE3ZcgcvqqffZXqxQkaI/83ro6JZ4P
ubml0PUnAnkdmnBCpbClbZMzmo3ELZ0EQwsvkJFDMQmiRhda4nBooUW7zXOIb7Wx
bE9THrt3cdZP5uAgVfgguUNE4fZMN8ATEDhdSsLklJe2GvihKuZVA6uuSkWAsK6u
MGo76xpPwYs3eUdLjtANS83a6/F/fhkX1GXs7zbQjh+Inzk8jhEdEogl9jPs/oDj
KjbkUpFlsCWwAZGoeKlmX7c4OGuD5c+FEH+2nYHvYl8y1E/K5SDt9Uocio8XuxbD
ZOzhw7LMSGkD1MZxpDzsCZY1emkSNd88NFj+9U8VssIDDVMYwKMsHKfjc0x5OlzQ
1f6ST0xCkwydDHHGRKKxFC4y6H6fV9sgf9OPK/65z94Rx72+mfvTyizShjxYSRpl
sH9otU4parl8roD0KsVTfXZoYrYXzK6cXBn1BO/OEqWlu++Dd9MiGaUGKd22fXER
qNWoRAKlNn2b6EehD2D8WaAoliPURjkB0Lb/FpP9unI93Twg6NxBXAj734nctukR
b3kE08RydJV70eJsvEftF5hbED4HacGx9pzisaSz6t9AKiuSoF6uoCtlTIYatyfZ
kQA4wg50hAJqTynOQ09ArRHEchtB/7uvWZSBGJ7+zlzRGKx99P3oDZD+Y5D8bmUs
3PV6FnAp+IRSlnsQ6hChkwBoQUcngcfGSkBRvmGjsGercCetRRwBOfh9fbX2ruw4
mzRYrGnz9eBtepkJXDRjD6yvhNfQMCSkm6l9zMWxKvFbv5g2ae2SLrEt/x3MP2/G
```

## Salphaseion

This phase can be split into multiple sections, only some are currently decoded

> d b b i b f b h c c b e g b i h a b e b e i h b e g g e g e b e b b g e h h e b h h f b a b f d h b e f f c d b b f c c c g b f b e e g g e c b e d c i b f b f f g i g b e e e a b e **a b b a b b a b a b b a a a a b a b b b a b a a a b b b a a b a a b b a b a a b a b b b b a a a a b b b a a b b a b b b a b a b a b b a b b a b a b b a b b a a a b b a b a a b a b b b a a b b a b b b a b a a**  f a e d g g e e d f c b d a b h h g g c a d c f e d d g f d g b g i g a a e d g g i a f a e c g h g g c d a i h e h a h b a h i g c e i f g b f g e f g a i f a b i f a g a e g e a c g b b e a g f g g e e g g a f b a c g f c d b e i f f a a f c i d a h g d e e f g h h c g g a e g d e b h h e g e g h c e g a d f b d i a g e f c i c g g i f d c g a a g g f b i g a i c f b h e c a e c b c e i a i c e b g b g i e c d e g g f g e g a e d g g f i i c i i i f i f h g g c g f g d c d g g e f c b e e i g e f i b g i b g g g h h f b c g i f d e h e d f d a g i c d b h i c g a i e d a e h a h g h h c i h d g h f h b i i c e c b i i c h i h i i i g i d d g e h h d f d c h c b a f g f b h a h e a g e g e c a f e h g c f g g g g c a g f h h g h b a i h i d i e h h f d e g g d g c i h g g g g g h a d a h i g i g b g e c g e d f c d g g a c c d e h i i c i g f b f f h g g a e i d b b e i b b e i i f d g f d h i e e e i e e e c i f d g d a h d i g g f h e g f i a f f i g g b c b c e h c e a b f b e d b i i b f b f d e d e e h g i g f a a i g g a g b e i i c h i e d i f b e h g b c c a h h b i i b i b b i b d c b a h a i d h f a h i i h i c **z** a g d a f a o a h e i e c g g c h g i c b b h c g b e h c f c o a b i c f d h h c d b b c a g b d a i o b b g b e a d e d d e **z** c f o b f d h g d o b d g o o i i g d o c d a o o f i d h **z** s h a b e f o u r f i r s t h i n t i s y o u r l a s t c o m m a n d 
> U 2 F s d G V k X 1 8 6 t Y U 0 h V J B X X U n B U O 7 C 0 + X 4 K U W n W k C v o Z S x b R D 3 w N s G W V H e f v d r d 9 z **a b b a a b a b a b b a b b b a a b b b a b a a a b b a a b a b a b b b a a b a** Q v X 0 t 8 v 3 j P B 4 o k p s p x e b R i 6 s E 1 B M l 5 H I 8 R k u + K e j U q T v d W O X 6 n Q j S p e p X w G u N / j J 
> s h a b e f a n s t o o

The two "abba" sections can be decoded first, where we translate a=0, b=1, and interpret the resulting string as binary representation of ascii characters:

[a b b a b b a b a b b a a a a b a b b b a b a a a b b b a a b a a b b a b a a b a b b b b a a a a b b b a a b b a b b b a b a b a b b a b b a b a b b a b b a a a b b a b a a b a b b b a a b b a b b b a b a a](https://gchq.github.io/CyberChef/#recipe=Remove_whitespace(true,true,true,true,true,false)Substitute('ab','01')From_Binary('Space',8)&input=YSBiIGIgYSBiIGIgYSBiIGEgYiBiIGEgYSBhIGEgYiBhIGIgYiBiIGEgYiBhIGEgYSBiIGIgYiBhIGEgYiBhIGEgYiBiIGEgYiBhIGEgYiBhIGIgYiBiIGIgYSBhIGEgYSBiIGIgYiBhIGEgYiBiIGEgYiBiIGIgYSBiIGEgYiBhIGIgYiBhIGIgYiBhIGIgYSBiIGIgYSBiIGIgYSBhIGEgYiBiIGEgYiBhIGEgYiBhIGIgYiBiIGEgYSBiIGIgYSBiIGIgYiBhIGIgYSBh) -> "matrixsumlist"

[a b b a a b a b a b b a b b b a a b b b a b a a a b b a a b a b a b b b a a b a](https://gchq.github.io/CyberChef/#recipe=Remove_whitespace(true,true,true,true,true,false)Substitute('ab','01')From_Binary('Space',8)&input=YSBiIGIgYSBhIGIgYSBiIGEgYiBiIGEgYiBiIGIgYSBhIGIgYiBiIGEgYiBhIGEgYSBiIGIgYSBhIGIgYSBiIGEgYiBiIGIgYSBhIGIgYQ) -> "enter"

Next, we see two occurances of "shabef", and the English text "our first hint is your last command". To get into Salphaseion, we had to sha256() a string, which gives us the mapping shabef=sha256 -> b=2,e=5, f=6, or, a=1 .. z = 26. But, the rest of the text doesn't seem to decode the same way. We notice that "z" seems to be a separator for various segments, and comes before other substrings, we have:
1. a g d a f a o a h e i e c g g c h g i c b b h c g b e h c f c o a b i c f d h h c d b b c a g b d a i o b b g b e a d e d d e
2. c f o b f d h g d o b d g o o i i g d o c d a o o f i d h

Again, using a1z26 doesn't seem to get us anywhere, but if we look at which characters are available it will give us a clue. "a" through "i" and "o", 10 characters, and we know that a=1, and i=9, we can guess that "o" is "0", this updates our decode to:
1. 174161018595377387932283725836301293648834223172419022725145445
2. 36026487402470099740341006948

Through some trial and error, we find that these need to be shifted to base 16, then decoded as hex representation of ascii
1. [lastwordsbeforearchichoice](https://gchq.github.io/CyberChef/#recipe=Remove_whitespace(true,true,true,true,true,false)Substitute('abcdefghio','1234567890')To_Base(16)From_Hex('Auto')&input=YSBnIGQgYSBmIGEgbyBhIGggZSBpIGUgYyBnIGcgYyBoIGcgaSBjIGIgYiBoIGMgZyBiIGUgaCBjIGYgYyBvIGEgYiBpIGMgZiBkIGggaCBjIGQgYiBiIGMgYSBnIGIgZCBhIGkgbyBiIGIgZyBiIGUgYSBkIGUgZCBkIGU)
2. [thispassword](https://gchq.github.io/CyberChef/#recipe=Remove_whitespace(true,true,true,true,true,false)Substitute('abcdefghio','1234567890')To_Base(16)From_Hex('Auto')&input=IGMgZiBvIGIgZiBkIGggZyBkIG8gYiBkIGcgbyBvIGkgaSBnIGQgbyBjIGQgYSBvIG8gZiBpIGQgaA)

### AES Blob
The following follows the same formatting as previous openssl base64-encoded AES blobs that we encounted in previous stages
> U 2 F s d G V k X 1 8 6 t Y U 0 h V J B X X U n B U O 7 C 0 + X 4 K U W n W k C v o Z S x b R D 3 w N s G W V H e f v d r d 9 z
> Q v X 0 t 8 v 3 j P B 4 o k p s p x e b R i 6 s E 1 B M l 5 H I 8 R k u + K e j U q T v d W O X 6 n Q j S p e p X w G u N / j J
