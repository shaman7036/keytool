CLI-застосунок для роботи з клоном YubiKey 4 MAC-SHA1 challenge-response (сумісний із KeePassXC), 
читання серійного номера, програмування слотів конфігурації.

------- збирання ----------

make deps             # встановлення залежностей
make                  # збирає ./stkeytool
sudo make install     # встановлює бінарник + udev-правило
sudo make uninstall   # видаляє обидва
make clean

-------  Команди ----------

stkeytool status
stkeytool serial
stkeytool chal <1|2> <hex|-> [40-hex-key]
stkeytool test <1|2>
stkeytool program <1|2> <40-hex-key>
stkeytool keygen

-- status
Стан пристрою:

$ stkeytool status
version    4.3.7
pgmSeq     13
touchLevel 0x0003
slot1      valid
slot2      valid

-- stkeytool serial

Серійний номер пристрою (десяткове число)

-- stkeytool keygen

Генерує випадковий 20-байтовий ключ і друкує його 40 символами hex
(джерело — `/dev/urandom`).

$ stkeytool keygen
83166915ab98b1c5595a6823e212d763f8fe618a


-- stkeytool chal <1|2> <hex|-> [40-hex-key]

Надсилає challenge у слот 1 або 2 і друкує відповідь HMAC-SHA1 (20 байт, hex).

- "hex" - challenge від 1 до 64 байт (до 128 символів hex, регістр довільний);
  коротші за 64 байти доповнюються PKCS7-подібним способом.
- "-" замість hex — прочати до 64 байтів сирих даних з stdin:

  printf 'hello' | stkeytool chal 2 -

- Необов'язковий 4-й аргумент — ключ (40 hex символів): застосунок сам
  обчислить HMAC локально і порівняє з відповіддю пристрою
  ("local hmac MATCH" / "local hmac MISMATCH"; при розбіжності — код виходу 1).

$ stkeytool chal 2 00112233445566778899aabbccddeeff 83166915ab98b1c5595a6823e212d763f8fe618a
response   9f2c...
local hmac MATCH

-- stkeytool test <1|2>

Швидка перевірка слота без ключа: випадковий 1-байтовий challenge із
доповненням (так само, як "performTestChallenge" у KeePassXC), друкує challenge
і відповідь пристрою. Локальної перевірки не робить.

-- stkeytool program <1|2> <40-hex-key>

Програмує слот під HMAC-SHA1 challenge-response заданим ключем.

$ stkeytool program 2 83166915ab98b1c5595a6823e212d763f8fe618a
programmed slot 2, pgmSeq 13 -> 14

Попередження:  Записується повна конфігурація слота усе, що там було, втрачається; 
- Слот 1 типово зайнятий базовою OTP-конфігурацією; для challenge-response
  зазвичай обирають слот 2.
- Якщо слот захищено access code, пристрій відхилить запис — застосунок
  повідомить `pgmSeq unchanged ... write rejected` (код виходу 1).
- Успіх фіксується лише за зміною `pgmSeq` — не прибирайте цю перевірку.

-- Приклад: повний цикл

KEY=$(stkeytool keygen)            # 1. згенерувати ключ
stkeytool program 2 "$KEY"         # 2. запрограмувати слот 2
stkeytool test 2                   # 3. спонтанна перевірка
stkeytool chal 2 001122334455 "$KEY"   # 4. перевірка з локальним HMAC
echo "$KEY" | stkeytool chal 2 -   # 5. байти з stdin
