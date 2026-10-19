# Sunset

**Author:** Incendio

---

### Challenge Description
>
> Vice City never sleeps. Behind its beautiful sunsets and glamorous beaches lies a world of secrets, shady deals, and hidden messages.
>
> A photograph named `sunset.jpg` has surfaced. It looks like an ordinary snapshot of the city, but looks can be deceiving. Someone went to great lengths to hide something inside it, and the truth is waiting for someone clever enough to uncover it.
>
> Dig deeper, follow the clues, and reveal what the image is hiding.
>

The challenge provides one file:

- **sunset.jpg** — a seemingly normal JPEG image with nothing suspicious at first glance

---

### Step 1: Image Analysis

The image looks ordinary, but JPEG files can carry hidden data through **Steghide**. Since Steghide protects embedded data with a passphrase, guessing common passwords is unlikely to help. The intended approach is to use **Stegseek** with the RockYou wordlist.

---

### Step 2: Searching with RockYou

Run Stegseek against the image and the RockYou wordlist (adjust the path if needed):

`stegseek sunset.jpg /usr/share/wordlists/rockyou.txt`

Stegseek finds the passphrase "zacefronxoxo" from the wordlist and writes the recovered data to `sunset.jpg.out`.

---

### Step 3: Reading the Flag

Display the extracted data to reveal the flag:

`cat sunset.jpg.out`

`Securinets_fst{seek_th3_st3g}`
