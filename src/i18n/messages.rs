//! Every user-facing string, in every language.
//!
//! Terminology is kept consistent per language rather than translated word by
//! word. In particular the traditional Chinese entries use Taiwanese usage
//! (檔案, 設定, 網路, 金鑰) rather than a character-level conversion of the
//! simplified text, which is the usual way this kind of localisation reads
//! wrong to a reader in Taiwan.

use crate::messages;

messages! {
    // -- shared ------------------------------------------------------------

    fn cancelled() =>
        en: "cancelled",
        zh_hans: "已取消",
        zh_hant: "已取消",
        ja: "キャンセルしました";

    fn yes_no_hint() =>
        en: "[y/N]",
        zh_hans: "[y/N]",
        zh_hant: "[y/N]",
        ja: "[y/N]";

    fn type_to_continue(word: &str) =>
        en: "Type {word} to continue: ",
        zh_hans: "输入 {word} 以继续：",
        zh_hant: "輸入 {word} 以繼續：",
        ja: "続けるには {word} と入力してください: ";

    fn label_warning() =>
        en: "warning:",
        zh_hans: "警告：",
        zh_hant: "警告：",
        ja: "警告:";

    fn label_error() =>
        en: "error:",
        zh_hans: "错误：",
        zh_hant: "錯誤：",
        ja: "エラー:";

    fn none_placeholder() =>
        en: "-",
        zh_hans: "-",
        zh_hant: "-",
        ja: "-";

    // -- init --------------------------------------------------------------

    fn init_heading() =>
        en: "Creating a new vault",
        zh_hans: "正在创建新的保险库",
        zh_hant: "正在建立新的保險庫",
        ja: "新しい保管庫を作成します";

    fn init_only_protection() =>
        en: "Your email and password together are the only thing protecting these secrets.",
        zh_hans: "邮箱与密码合在一起，是保护这些密钥的唯一屏障。",
        zh_hant: "電子郵件與密碼合在一起，是保護這些金鑰的唯一屏障。",
        ja: "これらのシークレットを守るのは、メールアドレスとパスワードの組み合わせだけです。";

    /// The word emphasised inside [`init_only_protection`]; it must appear
    /// verbatim in that sentence in every language.
    fn init_only_word() =>
        en: "only",
        zh_hans: "唯一",
        zh_hant: "唯一",
        ja: "だけ";

    fn init_no_recovery() =>
        en: "There is no recovery. If you forget either of them, the accounts in this vault \
             are gone for good — so make an encrypted backup once you have added them.",
        zh_hans: "没有任何找回机制。任何一个忘了，保险库里的账号都将永久丢失 —— \
                  所以账号加完之后请立刻做一份加密备份。",
        zh_hant: "沒有任何找回機制。任何一個忘了，保險庫裡的帳號都將永久遺失 —— \
                  所以帳號加完之後請立刻做一份加密備份。",
        ja: "復旧手段はありません。どちらかを忘れると、この保管庫のアカウントは永久に失われます。\
             アカウントを追加したら、必ず暗号化バックアップを作成してください。";

    fn init_kdf_note(memory: u64, passes: u32) =>
        en: "Key derivation: Argon2id, {memory} MiB, {passes} passes. \
             Unlocking will take about a second.",
        zh_hans: "密钥派生：Argon2id，{memory} MiB，{passes} 轮。解锁大约需要一秒。",
        zh_hant: "金鑰衍生：Argon2id，{memory} MiB，{passes} 輪。解鎖大約需要一秒。",
        ja: "鍵導出: Argon2id、{memory} MiB、{passes} パス。ロック解除に約 1 秒かかります。";

    fn init_choose_password() =>
        en: "Choose a master password: ",
        zh_hans: "请设置主密码：",
        zh_hant: "請設定主密碼：",
        ja: "マスターパスワードを設定してください: ";

    fn init_confirm_password() =>
        en: "Confirm master password: ",
        zh_hans: "请再次输入主密码：",
        zh_hant: "請再次輸入主密碼：",
        ja: "マスターパスワードをもう一度入力してください: ";

    fn init_done() =>
        en: "vault created",
        zh_hans: "保险库已创建",
        zh_hant: "保險庫已建立",
        ja: "保管庫を作成しました";

    fn init_already_exists(path: &str) =>
        en: "a vault already exists at {path}",
        zh_hans: "{path} 已经存在一个保险库",
        zh_hant: "{path} 已經存在一個保險庫",
        ja: "{path} にはすでに保管庫があります";

    fn password_too_short(minimum: usize) =>
        en: "the master password must be at least {minimum} characters",
        zh_hans: "主密码至少需要 {minimum} 个字符",
        zh_hant: "主密碼至少需要 {minimum} 個字元",
        ja: "マスターパスワードは {minimum} 文字以上にしてください";

    fn password_mismatch() =>
        en: "the two entries did not match",
        zh_hans: "两次输入不一致",
        zh_hant: "兩次輸入不一致",
        ja: "入力が一致しません";

    // -- unlocking ---------------------------------------------------------

    fn prompt_master_password() =>
        en: "Master password: ",
        zh_hans: "主密码：",
        zh_hant: "主密碼：",
        ja: "マスターパスワード: ";



    fn prompt_backup_password() =>
        en: "Backup password: ",
        zh_hans: "备份密码：",
        zh_hant: "備份密碼：",
        ja: "バックアップのパスワード: ";


    fn try_again() =>
        en: "Try again?",
        zh_hans: "要重试吗？",
        zh_hant: "要重試嗎？",
        ja: "もう一度試しますか?";

    fn vault_is_locked() =>
        en: "the vault is locked.",
        zh_hans: "保险库已锁定。",
        zh_hant: "保險庫已鎖定。",
        ja: "保管庫はロックされています。";

    fn locked_error() =>
        en: "the vault is locked",
        zh_hans: "保险库已锁定",
        zh_hant: "保險庫已鎖定",
        ja: "保管庫はロックされています";

    fn keys_erased() =>
        en: "keys erased from memory",
        zh_hans: "密钥已从内存中擦除",
        zh_hant: "金鑰已從記憶體中抹除",
        ja: "鍵をメモリから消去しました";

    fn locked_goodbye() =>
        en: "locked.",
        zh_hans: "已锁定。",
        zh_hant: "已鎖定。",
        ja: "ロックしました。";

    // -- listing and codes -------------------------------------------------

    fn column_issuer() =>
        en: "ISSUER",
        zh_hans: "发行方",
        zh_hant: "發行方",
        ja: "発行元";

    fn column_account() =>
        en: "ACCOUNT",
        zh_hans: "账号",
        zh_hant: "帳號",
        ja: "アカウント";

    fn column_type() =>
        en: "TYPE",
        zh_hans: "类型",
        zh_hant: "類型",
        ja: "種類";

    fn column_code() =>
        en: "CODE",
        zh_hans: "验证码",
        zh_hant: "驗證碼",
        ja: "コード";

    fn column_field() =>
        en: "FIELD",
        zh_hans: "字段",
        zh_hant: "欄位",
        ja: "項目";

    fn column_value() =>
        en: "VALUE",
        zh_hans: "值",
        zh_hant: "值",
        ja: "値";

    fn column_setting() =>
        en: "SETTING",
        zh_hans: "设置项",
        zh_hant: "設定項",
        ja: "設定";

    fn no_accounts_yet() =>
        en: "no accounts yet. Use `add` or `import` to get started.",
        zh_hans: "还没有任何账号。用 `add` 或 `import` 开始。",
        zh_hant: "還沒有任何帳號。用 `add` 或 `import` 開始。",
        ja: "アカウントがまだありません。`add` または `import` で追加してください。";

    fn no_accounts_match() =>
        en: "no accounts match.",
        zh_hans: "没有匹配的账号。",
        zh_hant: "沒有符合的帳號。",
        ja: "一致するアカウントがありません。";

    fn seconds_left(seconds: u32) =>
        en: "{seconds}s",
        zh_hans: "{seconds} 秒",
        zh_hant: "{seconds} 秒",
        ja: "{seconds} 秒";

    fn counter_is(counter: u64) =>
        en: "counter {counter}",
        zh_hans: "计数器 {counter}",
        zh_hant: "計數器 {counter}",
        ja: "カウンター {counter}";

    fn counter_advanced(counter: u64) =>
        en: "counter advanced to {counter}",
        zh_hans: "计数器已递增至 {counter}",
        zh_hant: "計數器已遞增至 {counter}",
        ja: "カウンターを {counter} に進めました";

    fn not_time_based(name: &str) =>
        en: "{name} is time-based; it has no counter",
        zh_hans: "{name} 是基于时间的，没有计数器",
        zh_hant: "{name} 是基於時間的，沒有計數器",
        ja: "{name} は時刻ベースのため、カウンターはありません";

    fn no_account_matches(needle: &str) =>
        en: "no account matches `{needle}`",
        zh_hans: "没有账号匹配 `{needle}`",
        zh_hant: "沒有帳號符合 `{needle}`",
        ja: "`{needle}` に一致するアカウントはありません";

    fn ambiguous_name(needle: &str, count: usize, candidates: &str) =>
        en: "`{needle}` matches {count} accounts:\n{candidates}",
        zh_hans: "`{needle}` 匹配到 {count} 个账号：\n{candidates}",
        zh_hant: "`{needle}` 符合 {count} 個帳號：\n{candidates}",
        ja: "`{needle}` は {count} 件のアカウントに一致します:\n{candidates}";

    // -- account details ---------------------------------------------------

    fn field_issuer() =>
        en: "issuer",
        zh_hans: "发行方",
        zh_hant: "發行方",
        ja: "発行元";

    fn field_account() =>
        en: "account",
        zh_hans: "账号",
        zh_hant: "帳號",
        ja: "アカウント";

    fn field_type() =>
        en: "type",
        zh_hans: "类型",
        zh_hant: "類型",
        ja: "種類";

    fn field_created() =>
        en: "created",
        zh_hans: "创建于",
        zh_hant: "建立於",
        ja: "作成日時";

    fn field_updated() =>
        en: "updated",
        zh_hans: "更新于",
        zh_hant: "更新於",
        ja: "更新日時";

    fn field_notes() =>
        en: "notes",
        zh_hans: "备注",
        zh_hant: "備註",
        ja: "メモ";

    fn secret_not_shown() =>
        en: "the shared secret is not shown here; use `reveal` if you need it.",
        zh_hans: "这里不显示密钥；确实需要的话用 `reveal`。",
        zh_hant: "這裡不顯示金鑰；確實需要的話用 `reveal`。",
        ja: "共有シークレットはここには表示されません。必要なら `reveal` を使ってください。";
}

messages! {
    // -- adding and importing ----------------------------------------------

    fn add_intro() =>
        en: "Paste an otpauth:// URI, or the Base32 secret the site showed you.",
        zh_hans: "粘贴 otpauth:// 链接，或网站给你的 Base32 密钥。",
        zh_hant: "貼上 otpauth:// 連結，或網站給你的 Base32 金鑰。",
        ja: "otpauth:// の URI か、サイトが表示した Base32 のシークレットを貼り付けてください。";

    fn prompt_secret_or_uri() =>
        en: "Secret or URI (hidden): ",
        zh_hans: "密钥或链接（不回显）：",
        zh_hant: "金鑰或連結（不回顯）：",
        ja: "シークレットまたは URI (非表示): ";

    fn prompt_uri() =>
        en: "otpauth:// URI (hidden): ",
        zh_hans: "otpauth:// 链接（不回显）：",
        zh_hant: "otpauth:// 連結（不回顯）：",
        ja: "otpauth:// URI (非表示): ";

    fn prompt_issuer_example() =>
        en: "Issuer (e.g. GitHub): ",
        zh_hans: "发行方（例如 GitHub）：",
        zh_hant: "發行方（例如 GitHub）：",
        ja: "発行元 (例: GitHub): ";

    fn prompt_account_example() =>
        en: "Account (e.g. you@example.com): ",
        zh_hans: "账号（例如 you@example.com）：",
        zh_hant: "帳號（例如 you@example.com）：",
        ja: "アカウント (例: you@example.com): ";

    fn prompt_digits() =>
        en: "Digits",
        zh_hans: "位数",
        zh_hant: "位數",
        ja: "桁数";

    fn prompt_period() =>
        en: "Period in seconds",
        zh_hans: "周期（秒）",
        zh_hant: "週期（秒）",
        ja: "周期 (秒)";

    fn prompt_algorithm() =>
        en: "Algorithm [SHA1]: ",
        zh_hans: "算法 [SHA1]：",
        zh_hant: "演算法 [SHA1]：",
        ja: "アルゴリズム [SHA1]: ";

    fn nothing_entered() =>
        en: "nothing entered",
        zh_hans: "没有输入任何内容",
        zh_hant: "沒有輸入任何內容",
        ja: "何も入力されていません";

    fn not_uri_or_base32() =>
        en: "that is neither an otpauth:// URI nor a valid Base32 secret",
        zh_hans: "这既不是 otpauth:// 链接，也不是有效的 Base32 密钥",
        zh_hant: "這既不是 otpauth:// 連結，也不是有效的 Base32 金鑰",
        ja: "otpauth:// URI でも、有効な Base32 シークレットでもありません";

    fn unknown_algorithm(name: &str) =>
        en: "unknown algorithm `{name}`",
        zh_hans: "未知的算法 `{name}`",
        zh_hant: "未知的演算法 `{name}`",
        ja: "不明なアルゴリズム `{name}`";

    fn not_a_number(text: &str) =>
        en: "`{text}` is not a number",
        zh_hans: "`{text}` 不是数字",
        zh_hant: "`{text}` 不是數字",
        ja: "`{text}` は数値ではありません";

    fn import_usage() =>
        en: "usage: import uri [<uri>] | import qr <image>... | import file <path>",
        zh_hans: "用法：import uri [<链接>] | import qr <图片>... | import file <文件>",
        zh_hant: "用法：import uri [<連結>] | import qr <圖片>... | import file <檔案>",
        ja: "使い方: import uri [<URI>] | import qr <画像>... | import file <ファイル>";

    fn give_an_image() =>
        en: "give at least one image file",
        zh_hans: "至少要给一个图片文件",
        zh_hant: "至少要給一個圖片檔案",
        ja: "画像ファイルを少なくとも 1 つ指定してください";

    fn nothing_to_import() =>
        en: "nothing to import",
        zh_hans: "没有可导入的内容",
        zh_hant: "沒有可匯入的內容",
        ja: "インポートするものがありません";

    fn nothing_added() =>
        en: "nothing added",
        zh_hans: "没有添加任何账号",
        zh_hant: "沒有新增任何帳號",
        ja: "何も追加されませんでした";

    fn already_in_vault(name: &str) =>
        en: "`{name}` is already in the vault",
        zh_hans: "`{name}` 已经在保险库里了",
        zh_hant: "`{name}` 已經在保險庫裡了",
        ja: "`{name}` はすでに保管庫にあります";

    fn add_anyway() =>
        en: "Add it anyway?",
        zh_hans: "仍然添加吗？",
        zh_hant: "仍然新增嗎？",
        ja: "それでも追加しますか?";

    fn back_up_reminder() =>
        en: "run `export encrypted <path>` to back this up — there is no recovery.",
        zh_hans: "用 `export encrypted <文件>` 做一份备份 —— 没有任何找回机制。",
        zh_hant: "用 `export encrypted <檔案>` 做一份備份 —— 沒有任何找回機制。",
        ja: "`export encrypted <パス>` でバックアップしてください。復旧手段はありません。";

    fn qr_no_code(path: &str) =>
        en: "no QR code found in {path}. Crop the screenshot to the code and try again.",
        zh_hans: "在 {path} 里没有找到二维码。把截图裁剪到只剩二维码再试一次。",
        zh_hant: "在 {path} 裡沒有找到 QR code。把截圖裁切到只剩 QR code 再試一次。",
        ja: "{path} に QR コードが見つかりません。スクリーンショットをコードだけに切り抜いて再度お試しください。";

    fn qr_unreadable(codes: &str, path: &str) =>
        en: "found {codes} in {path} but could not read any of them; \
             try a sharper or larger image",
        zh_hans: "在 {path} 里找到 {codes}，但一个都读不出来；换一张更清晰或更大的图试试",
        zh_hant: "在 {path} 裡找到 {codes}，但一個都讀不出來；換一張更清晰或更大的圖試試",
        ja: "{path} で {codes}を検出しましたが、いずれも読み取れませんでした。より鮮明か大きな画像でお試しください";

    fn qr_cannot_open(path: &str) =>
        en: "cannot read {path} as an image",
        zh_hans: "无法把 {path} 当作图片读取",
        zh_hant: "無法把 {path} 當作圖片讀取",
        ja: "{path} を画像として読み込めません";

    fn not_an_otpauth_value() =>
        en: "not an otpauth:// or otpauth-migration:// value. \
             If you have a plain Base32 secret, use `add` instead.",
        zh_hans: "不是 otpauth:// 或 otpauth-migration:// 的内容。\
                  如果你手上是一串 Base32 密钥，请改用 `add`。",
        zh_hant: "不是 otpauth:// 或 otpauth-migration:// 的內容。\
                  如果你手上是一串 Base32 金鑰，請改用 `add`。",
        ja: "otpauth:// でも otpauth-migration:// でもありません。\
             Base32 のシークレットをお持ちなら `add` を使ってください。";

    fn migration_unreadable() =>
        en: "this looks like a Google Authenticator export, but it could not be read",
        zh_hans: "这看起来是谷歌验证器的导出内容，但无法解析",
        zh_hant: "這看起來是 Google Authenticator 的匯出內容，但無法解析",
        ja: "Google Authenticator のエクスポートのようですが、読み取れませんでした";

    // -- deleting, renaming, revealing -------------------------------------

    fn about_to_delete(name: &str) =>
        en: "About to delete {name}.",
        zh_hans: "即将删除 {name}。",
        zh_hant: "即將刪除 {name}。",
        ja: "{name} を削除しようとしています。";

    fn delete_lockout_warning() =>
        en: "if this is your only copy of that second factor, you will be locked out.",
        zh_hans: "如果这是你这个二次验证的唯一一份，删掉之后你将无法登录。",
        zh_hant: "如果這是你這個雙重驗證的唯一一份，刪掉之後你將無法登入。",
        ja: "この二要素認証の唯一の控えであれば、削除するとログインできなくなります。";

    fn delete_confirm() =>
        en: "Delete it?",
        zh_hans: "确认删除吗？",
        zh_hant: "確認刪除嗎？",
        ja: "削除しますか?";

    fn deleted(name: &str) =>
        en: "deleted {name}",
        zh_hans: "已删除 {name}",
        zh_hant: "已刪除 {name}",
        ja: "{name} を削除しました";

    fn no_such_account() =>
        en: "no such account",
        zh_hans: "没有这个账号",
        zh_hant: "沒有這個帳號",
        ja: "そのアカウントはありません";

    fn no_such_account_named(name: &str) =>
        en: "no such account: {name}",
        zh_hans: "没有这个账号：{name}",
        zh_hant: "沒有這個帳號：{name}",
        ja: "そのアカウントはありません: {name}";

    fn rename_intro(name: &str) =>
        en: "Renaming {name}. Leave a field empty to keep it.",
        zh_hans: "正在重命名 {name}。留空表示保持不变。",
        zh_hant: "正在重新命名 {name}。留空表示保持不變。",
        ja: "{name} の名前を変更します。空欄にすると現在の値を保ちます。";

    fn prompt_issuer_default(current: &str) =>
        en: "Issuer [{current}]: ",
        zh_hans: "发行方 [{current}]：",
        zh_hant: "發行方 [{current}]：",
        ja: "発行元 [{current}]: ";

    fn prompt_account_default(current: &str) =>
        en: "Account [{current}]: ",
        zh_hans: "账号 [{current}]：",
        zh_hant: "帳號 [{current}]：",
        ja: "アカウント [{current}]: ";

    fn renamed() =>
        en: "renamed",
        zh_hans: "已重命名",
        zh_hant: "已重新命名",
        ja: "名前を変更しました";

    fn reveal_warning(name: &str) =>
        en: "this prints the shared secret for {name} in plain text. Anyone reading your \
             screen, your scrollback, or a terminal log will have permanent access to this \
             second factor.",
        zh_hans: "这会以明文打印 {name} 的密钥。任何能看到你屏幕、终端回滚记录或终端日志的人，\
                  都将永久拥有这个二次验证。",
        zh_hant: "這會以明文列出 {name} 的金鑰。任何能看到你螢幕、終端機捲動紀錄或終端機日誌的人，\
                  都將永久擁有這個雙重驗證。",
        ja: "{name} の共有シークレットを平文で表示します。画面・スクロールバック・端末ログを\
             見られる相手は、この二要素認証を恒久的に利用できるようになります。";
}

messages! {
    // -- backup, export, restore -------------------------------------------

    fn vault_is_empty() =>
        en: "the vault is empty",
        zh_hans: "保险库是空的",
        zh_hant: "保險庫是空的",
        ja: "保管庫は空です";

    fn backup_uses_master_password() =>
        en: "the backup will be keyed on the same email and password you unlock with.",
        zh_hans: "备份将使用你解锁时用的同一组邮箱与密码。",
        zh_hant: "備份將使用你解鎖時用的同一組電子郵件與密碼。",
        ja: "バックアップは、ロック解除に使うのと同じメールアドレスとパスワードで暗号化されます。";


    fn choose_backup_password() =>
        en: "Choose a password for this backup file.",
        zh_hans: "为这个备份文件设置一个密码。",
        zh_hant: "為這個備份檔案設定一個密碼。",
        ja: "このバックアップファイル用のパスワードを設定してください。";

    fn wrote_to(accounts: &str, path: &str) =>
        en: "wrote {accounts} to {path}",
        zh_hans: "已将 {accounts}写入 {path}",
        zh_hant: "已將 {accounts}寫入 {path}",
        ja: "{accounts}を {path} に書き出しました";

    fn keep_backup_elsewhere() =>
        en: "keep this somewhere other than the machine holding the vault.",
        zh_hans: "把它放在保险库所在机器之外的地方。",
        zh_hant: "把它放在保險庫所在電腦之外的地方。",
        ja: "保管庫のあるマシンとは別の場所に保存してください。";

    fn plaintext_export_warning(secrets: &str, path: &str) =>
        en: "this writes every one of your {secrets} to {path} with no encryption at all. \
             Anyone who reads that file owns your second factors.",
        zh_hans: "这会把你全部 {secrets}以完全未加密的形式写入 {path}。\
                  任何读到这个文件的人就拥有了你的全部二次验证。",
        zh_hant: "這會把你全部 {secrets}以完全未加密的形式寫入 {path}。\
                  任何讀到這個檔案的人就擁有了你的全部雙重驗證。",
        ja: "あなたの {secrets}すべてを、まったく暗号化せずに {path} へ書き出します。\
             このファイルを読めた人は、あなたの二要素認証をそのまま手に入れます。";

    fn plaintext_export_purpose() =>
        en: "Do this only to migrate to another authenticator, and delete the file afterwards.",
        zh_hans: "只有在迁移到别的验证器时才这么做，用完请立刻删除该文件。",
        zh_hant: "只有在遷移到別的驗證器時才這麼做，用完請立刻刪除該檔案。",
        ja: "他の認証アプリへ移行する場合にのみ実行し、終わったらファイルを削除してください。";

    fn delete_export_now() =>
        en: "delete that file as soon as you have imported it elsewhere.",
        zh_hans: "在别处导入完成后，请立刻删除该文件。",
        zh_hant: "在別處匯入完成後，請立刻刪除該檔案。",
        ja: "他所へのインポートが済んだら、すぐにそのファイルを削除してください。";

    fn accounts_in_file(accounts: &str, path: &str) =>
        en: "{accounts} in {path}",
        zh_hans: "{path} 中有 {accounts}",
        zh_hant: "{path} 中有 {accounts}",
        ja: "{path} には {accounts}があります";

    fn export_usage() =>
        en: "usage: export encrypted <path> | export plain <path>",
        zh_hans: "用法：export encrypted <文件> | export plain <文件>",
        zh_hant: "用法：export encrypted <檔案> | export plain <檔案>",
        ja: "使い方: export encrypted <パス> | export plain <パス>";

    fn wrong_backup_password() =>
        en: "wrong backup password, or the file is damaged",
        zh_hans: "备份密码错误，或文件已损坏",
        zh_hant: "備份密碼錯誤，或檔案已損壞",
        ja: "バックアップのパスワードが違うか、ファイルが破損しています";

    fn not_a_backup(path: &str) =>
        en: "{path} is not a neko-auth backup",
        zh_hans: "{path} 不是 neko-auth 的备份文件",
        zh_hant: "{path} 不是 neko-auth 的備份檔案",
        ja: "{path} は neko-auth のバックアップではありません";

    fn backup_truncated() =>
        en: "the backup is truncated",
        zh_hans: "备份文件不完整",
        zh_hant: "備份檔案不完整",
        ja: "バックアップが途中で切れています";

    // -- password change ---------------------------------------------------

    fn current_password_wrong() =>
        en: "the current password is not correct",
        zh_hans: "当前主密码不正确",
        zh_hant: "目前主密碼不正確",
        ja: "現在のマスターパスワードが正しくありません";


    fn backups_keep_own_password() =>
        en: "existing backup files still use whatever password they were made with.",
        zh_hans: "已有的备份文件仍使用它们创建时的密码。",
        zh_hant: "已有的備份檔案仍使用它們建立時的密碼。",
        ja: "既存のバックアップファイルは、作成時のパスワードのままです。";

    // -- doctor ------------------------------------------------------------

    fn doctor_heading() =>
        en: "Vault health",
        zh_hans: "保险库健康检查",
        zh_hant: "保險庫健康檢查",
        ja: "保管庫の状態";

    fn doctor_file() =>
        en: "file",
        zh_hans: "文件",
        zh_hant: "檔案",
        ja: "ファイル";

    fn doctor_accounts() =>
        en: "accounts",
        zh_hans: "账号数",
        zh_hant: "帳號數",
        ja: "アカウント数";

    fn doctor_sqlite() =>
        en: "sqlite integrity",
        zh_hans: "SQLite 完整性",
        zh_hant: "SQLite 完整性",
        ja: "SQLite 整合性";

    fn doctor_signature() =>
        en: "vault signature",
        zh_hans: "保险库签名",
        zh_hant: "保險庫簽章",
        ja: "保管庫の署名";

    fn doctor_wal() =>
        en: "write-ahead log",
        zh_hans: "预写日志",
        zh_hant: "預寫日誌",
        ja: "先行書き込みログ";

    fn status_ok() =>
        en: "ok",
        zh_hans: "正常",
        zh_hant: "正常",
        ja: "正常";

    fn status_mismatch() =>
        en: "MISMATCH",
        zh_hans: "不匹配",
        zh_hant: "不相符",
        ja: "不一致";

    fn status_active() =>
        en: "active",
        zh_hans: "已启用",
        zh_hant: "已啟用",
        ja: "有効";

    fn status_unavailable() =>
        en: "unavailable",
        zh_hans: "不可用",
        zh_hant: "不可用",
        ja: "利用不可";

    fn doctor_mac_warning() =>
        en: "the vault-wide signature does not match. Accounts may have been removed, or \
             this file replaced with an older copy. Individual accounts still decrypt.",
        zh_hans: "保险库整体签名不匹配。可能有账号被删除，或文件被换成了更早的副本。\
                  单个账号本身仍可正常解密。",
        zh_hant: "保險庫整體簽章不相符。可能有帳號被刪除，或檔案被換成了更早的副本。\
                  單個帳號本身仍可正常解密。",
        ja: "保管庫全体の署名が一致しません。アカウントが削除されたか、ファイルが古い複製に\
             差し替えられた可能性があります。個々のアカウントは引き続き復号できます。";

    fn wal_warning() =>
        en: "the write-ahead log is unavailable, which usually means a network or \
             cloud-synced folder. Move the vault to local disk.",
        zh_hans: "预写日志不可用，这通常意味着保险库放在网络盘或云同步目录里。请移到本地磁盘。",
        zh_hant: "預寫日誌不可用，這通常表示保險庫放在網路磁碟或雲端同步資料夾裡。請移到本機磁碟。",
        ja: "先行書き込みログが利用できません。ネットワークドライブやクラウド同期フォルダーに\
             置かれている可能性が高いです。保管庫をローカルディスクへ移動してください。";

    fn wal_warning_startup() =>
        en: "SQLite's write-ahead log is unavailable here, which usually means a network or \
             cloud-synced folder. A live vault in a synced folder will eventually be corrupted.",
        zh_hans: "这里无法使用 SQLite 的预写日志，通常意味着网络盘或云同步目录。\
                  把活动的保险库放在同步目录里迟早会损坏。",
        zh_hant: "這裡無法使用 SQLite 的預寫日誌，通常表示網路磁碟或雲端同步資料夾。\
                  把使用中的保險庫放在同步資料夾裡遲早會損壞。",
        ja: "ここでは SQLite の先行書き込みログを利用できません。ネットワークやクラウド同期の\
             フォルダーである可能性が高く、使用中の保管庫はいずれ破損します。";

    fn wal_warning_init() =>
        en: "this filesystem does not support SQLite's write-ahead log, which usually means \
             a network or cloud-synced folder. A live vault in a synced folder will be \
             corrupted sooner or later; keep it on local disk and use `export` for backups.",
        zh_hans: "这个文件系统不支持 SQLite 的预写日志，通常意味着网络盘或云同步目录。\
                  把活动的保险库放在同步目录里迟早会损坏；请放在本地磁盘，用 `export` 做备份。",
        zh_hant: "這個檔案系統不支援 SQLite 的預寫日誌，通常表示網路磁碟或雲端同步資料夾。\
                  把使用中的保險庫放在同步資料夾裡遲早會損壞；請放在本機磁碟，用 `export` 做備份。",
        ja: "このファイルシステムは SQLite の先行書き込みログに対応していません。ネットワークや\
             クラウド同期のフォルダーである可能性が高く、使用中の保管庫はいずれ破損します。\
             ローカルディスクに置き、バックアップは `export` を使ってください。";

    fn all_accounts_decrypt() =>
        en: "every account decrypts correctly",
        zh_hans: "所有账号都能正常解密",
        zh_hant: "所有帳號都能正常解密",
        ja: "すべてのアカウントが正しく復号できます";

    fn accounts_failed_to_decrypt(accounts: &str) =>
        en: "{accounts} failed to decrypt:",
        zh_hans: "{accounts}解密失败：",
        zh_hant: "{accounts}解密失敗：",
        ja: "{accounts}が復号できませんでした:";

    fn restore_damaged_from_backup() =>
        en: "restore these from a backup; the rest of the vault is unaffected.",
        zh_hans: "请从备份恢复这些账号；保险库的其余部分不受影响。",
        zh_hant: "請從備份還原這些帳號；保險庫的其餘部分不受影響。",
        ja: "これらはバックアップから復元してください。保管庫の他の部分に影響はありません。";

    fn integrity_warning() =>
        en: "the vault's integrity check failed: accounts may have been removed, or the file \
             replaced with an older copy. Your accounts are still readable; run `doctor`.",
        zh_hans: "保险库完整性校验失败：可能有账号被删除，或文件被换成了更早的副本。\
                  你的账号仍可读取；请运行 `doctor`。",
        zh_hant: "保險庫完整性驗證失敗：可能有帳號被刪除，或檔案被換成了更早的副本。\
                  你的帳號仍可讀取；請執行 `doctor`。",
        ja: "保管庫の整合性チェックに失敗しました。アカウントが削除されたか、ファイルが古い複製に\
             差し替えられた可能性があります。アカウントは読み取れます。`doctor` を実行してください。";

    fn account_integrity_failed(name: &str) =>
        en: "account `{name}` failed its integrity check; run `doctor`",
        zh_hans: "账号 `{name}` 完整性校验失败；请运行 `doctor`",
        zh_hant: "帳號 `{name}` 完整性驗證失敗；請執行 `doctor`",
        ja: "アカウント `{name}` の整合性チェックに失敗しました。`doctor` を実行してください";

    // -- config ------------------------------------------------------------

    fn unknown_setting(key: &str) =>
        en: "unknown setting `{key}`",
        zh_hans: "未知的设置项 `{key}`",
        zh_hant: "未知的設定項 `{key}`",
        ja: "不明な設定 `{key}`";

    fn setting_saved(key: &str, value: &str) =>
        en: "{key} = {value}",
        zh_hans: "{key} = {value}",
        zh_hant: "{key} = {value}",
        ja: "{key} = {value}";

    fn takes_effect_next_start() =>
        en: "takes effect the next time neko-auth starts.",
        zh_hans: "将在下次启动 neko-auth 时生效。",
        zh_hant: "將在下次啟動 neko-auth 時生效。",
        ja: "次回 neko-auth を起動したときに反映されます。";

    fn language_switched() =>
        en: "language changed",
        zh_hans: "语言已切换",
        zh_hant: "語言已切換",
        ja: "言語を変更しました";

    fn unknown_language(value: &str, known: &str) =>
        en: "unknown language `{value}` (expected auto, {known})",
        zh_hans: "未知的语言 `{value}`（可用：auto、{known}）",
        zh_hant: "未知的語言 `{value}`（可用：auto、{known}）",
        ja: "不明な言語 `{value}` (指定できるのは auto、{known})";

    fn unknown_kdf_profile(value: &str) =>
        en: "unknown profile `{value}` (interactive, moderate, paranoid)",
        zh_hans: "未知的档位 `{value}`（可用：interactive、moderate、paranoid）",
        zh_hant: "未知的檔位 `{value}`（可用：interactive、moderate、paranoid）",
        ja: "不明なプロファイル `{value}` (interactive、moderate、paranoid)";
}

messages! {
    // -- interactive session -----------------------------------------------

    fn banner_vault(path: &str) =>
        en: "vault: {path}",
        zh_hans: "保险库：{path}",
        zh_hant: "保險庫：{path}",
        ja: "保管庫: {path}";

    fn banner_autolock(seconds: u64) =>
        en: "auto-locks after {seconds}s idle",
        zh_hans: "闲置 {seconds} 秒后自动锁定",
        zh_hant: "閒置 {seconds} 秒後自動鎖定",
        ja: "{seconds} 秒操作がないと自動でロックします";

    fn banner_hint() =>
        en: "type `help` for commands, `exit` to leave",
        zh_hans: "输入 `help` 查看命令，`exit` 退出",
        zh_hant: "輸入 `help` 查看指令，`exit` 離開",
        ja: "`help` でコマンド一覧、`exit` で終了";

    fn prompt_locked_suffix() =>
        en: "(locked)",
        zh_hans: "(已锁定)",
        zh_hant: "(已鎖定)",
        ja: "(ロック中)";

    fn help_heading() =>
        en: "Commands",
        zh_hans: "命令",
        zh_hant: "指令",
        ja: "コマンド";

    fn help_copy_hint() =>
        en: "get <account> -c     copy the code to the clipboard",
        zh_hans: "get <账号> -c        把验证码复制到剪贴板",
        zh_hant: "get <帳號> -c        把驗證碼複製到剪貼簿",
        ja: "get <アカウント> -c  コードをクリップボードにコピー";

    fn help_qr_hint() =>
        en: "import qr a.png b.png   a multi-part Google export",
        zh_hans: "import qr a.png b.png   分成多张的谷歌验证器导出",
        zh_hant: "import qr a.png b.png   分成多張的 Google 驗證器匯出",
        ja: "import qr a.png b.png   複数枚に分かれた Google のエクスポート";

    fn unknown_command(name: &str) =>
        en: "unknown command `{name}`. Type `help` for the list.",
        zh_hans: "未知的命令 `{name}`。输入 `help` 查看列表。",
        zh_hant: "未知的指令 `{name}`。輸入 `help` 查看列表。",
        ja: "不明なコマンド `{name}`。`help` で一覧を表示します。";

    fn usage(form: &str) =>
        en: "usage: {form}",
        zh_hans: "用法：{form}",
        zh_hant: "用法：{form}",
        ja: "使い方: {form}";

    // -- command descriptions ----------------------------------------------

    fn cmd_ls() =>
        en: "list accounts",
        zh_hans: "列出账号",
        zh_hant: "列出帳號",
        ja: "アカウントを一覧表示";

    fn cmd_get() =>
        en: "show one account's current code",
        zh_hans: "显示某个账号当前的验证码",
        zh_hant: "顯示某個帳號目前的驗證碼",
        ja: "アカウントの現在のコードを表示";

    fn cmd_watch() =>
        en: "full-screen live view",
        zh_hans: "全屏实时看板",
        zh_hant: "全螢幕即時看板",
        ja: "全画面のライブ表示";

    fn cmd_add() =>
        en: "add an account",
        zh_hans: "添加账号",
        zh_hant: "新增帳號",
        ja: "アカウントを追加";

    fn cmd_import() =>
        en: "import from a URI, QR image, or file",
        zh_hans: "从链接、二维码图片或文件导入",
        zh_hant: "從連結、QR code 圖片或檔案匯入",
        ja: "URI・QR 画像・ファイルから取り込む";

    fn cmd_rm() =>
        en: "delete an account",
        zh_hans: "删除账号",
        zh_hant: "刪除帳號",
        ja: "アカウントを削除";

    fn cmd_rename() =>
        en: "change an account's name",
        zh_hans: "修改账号名称",
        zh_hant: "修改帳號名稱",
        ja: "アカウント名を変更";

    fn cmd_show() =>
        en: "show an account's settings",
        zh_hans: "查看账号的参数",
        zh_hant: "查看帳號的參數",
        ja: "アカウントの設定を表示";

    fn cmd_reveal() =>
        en: "print an account's secret",
        zh_hans: "打印账号的密钥",
        zh_hant: "列出帳號的金鑰",
        ja: "アカウントのシークレットを表示";

    fn cmd_export() =>
        en: "write a backup or a plaintext export",
        zh_hans: "写出备份或明文导出",
        zh_hant: "寫出備份或明文匯出",
        ja: "バックアップまたは平文エクスポートを書き出す";

    fn cmd_restore() =>
        en: "import from an encrypted backup",
        zh_hans: "从加密备份恢复",
        zh_hant: "從加密備份還原",
        ja: "暗号化バックアップから取り込む";

    fn cmd_passwd() =>
        en: "change the master password",
        zh_hans: "修改主密码",
        zh_hant: "變更主密碼",
        ja: "マスターパスワードを変更";

    fn cmd_doctor() =>
        en: "check the vault for damage",
        zh_hans: "检查保险库是否损坏",
        zh_hant: "檢查保險庫是否損壞",
        ja: "保管庫の破損を確認";

    fn cmd_config() =>
        en: "show or change settings",
        zh_hans: "查看或修改设置",
        zh_hant: "查看或修改設定",
        ja: "設定の表示・変更";

    fn cmd_lang() =>
        en: "switch language",
        zh_hans: "切换语言",
        zh_hant: "切換語言",
        ja: "言語を切り替える";

    fn cmd_lock() =>
        en: "erase the keys from memory now",
        zh_hans: "立即从内存中擦除密钥",
        zh_hant: "立即從記憶體中抹除金鑰",
        ja: "鍵を今すぐメモリから消去";

    fn cmd_update() =>
        en: "check for a new release",
        zh_hans: "检查新版本",
        zh_hant: "檢查新版本",
        ja: "新しいリリースを確認";

    fn cmd_help() =>
        en: "this list",
        zh_hans: "本列表",
        zh_hant: "本列表",
        ja: "この一覧";

    fn cmd_exit() =>
        en: "leave",
        zh_hans: "退出",
        zh_hant: "離開",
        ja: "終了";

    // -- watch view --------------------------------------------------------

    fn watch_title() =>
        en: "neko-auth · live codes",
        zh_hans: "neko-auth · 实时验证码",
        zh_hant: "neko-auth · 即時驗證碼",
        ja: "neko-auth · ライブコード";

    fn watch_filter(text: &str) =>
        en: "filter: {text}",
        zh_hans: "筛选：{text}",
        zh_hant: "篩選：{text}",
        ja: "絞り込み: {text}";

    fn watch_keys() =>
        en: "↑↓ select   / filter   c copy   q quit",
        zh_hans: "↑↓ 选择   / 筛选   c 复制   q 退出",
        zh_hant: "↑↓ 選擇   / 篩選   c 複製   q 離開",
        ja: "↑↓ 選択   / 絞り込み   c コピー   q 終了";

    fn watch_counter_label() =>
        en: "counter",
        zh_hans: "计数器",
        zh_hant: "計數器",
        ja: "カウンター";

    // -- clipboard ---------------------------------------------------------

    fn copied() =>
        en: "copied",
        zh_hans: "已复制",
        zh_hant: "已複製",
        ja: "コピーしました";

    fn copied_clears_in(seconds: u64) =>
        en: "copied; clears in {seconds}s",
        zh_hans: "已复制，{seconds} 秒后自动清空",
        zh_hant: "已複製，{seconds} 秒後自動清空",
        ja: "コピーしました。{seconds} 秒後に消去します";

    fn copied_cleared_after(seconds: u64) =>
        en: "copied; cleared after {seconds}s",
        zh_hans: "已复制，{seconds} 秒后已清空",
        zh_hant: "已複製，{seconds} 秒後已清空",
        ja: "コピーしました。{seconds} 秒後に消去しました";

    fn copied_named(name: &str, seconds: u64) =>
        en: "copied {name} — clears in {seconds}s",
        zh_hans: "已复制 {name} —— {seconds} 秒后清空",
        zh_hant: "已複製 {name} —— {seconds} 秒後清空",
        ja: "{name} をコピーしました — {seconds} 秒後に消去";

    fn copy_failed(reason: &str) =>
        en: "could not copy: {reason}",
        zh_hans: "复制失败：{reason}",
        zh_hant: "複製失敗：{reason}",
        ja: "コピーできません: {reason}";

    fn no_clipboard_support() =>
        en: "this build was compiled without clipboard support",
        zh_hans: "这个构建没有编译剪贴板支持",
        zh_hant: "這個組建沒有編譯剪貼簿支援",
        ja: "このビルドはクリップボード対応を含んでいません";

    fn no_qr_support() =>
        en: "this build was compiled without QR image support",
        zh_hans: "这个构建没有编译二维码图片支持",
        zh_hant: "這個組建沒有編譯 QR code 圖片支援",
        ja: "このビルドは QR 画像対応を含んでいません";

    // -- startup and paths -------------------------------------------------

    fn no_vault_here(path: &str) =>
        en: "no vault at {path}.\nRun `neko-auth init` to create one.",
        zh_hans: "{path} 没有保险库。\n运行 `neko-auth init` 创建一个。",
        zh_hant: "{path} 沒有保險庫。\n執行 `neko-auth init` 建立一個。",
        ja: "{path} に保管庫がありません。\n`neko-auth init` で作成してください。";

    fn not_a_vault(path: &str) =>
        en: "{path} is not a neko-auth vault",
        zh_hans: "{path} 不是 neko-auth 的保险库",
        zh_hant: "{path} 不是 neko-auth 的保險庫",
        ja: "{path} は neko-auth の保管庫ではありません";

    fn permissions_too_open(path: &str) =>
        en: "{path} is readable by other users on this machine. Run `chmod 600 {path}` to fix.",
        zh_hans: "{path} 可以被本机的其他用户读取。运行 `chmod 600 {path}` 修复。",
        zh_hant: "{path} 可以被本機的其他使用者讀取。執行 `chmod 600 {path}` 修復。",
        ja: "{path} はこのマシンの他のユーザーからも読み取れます。`chmod 600 {path}` で修正してください。";

    fn internal_error() =>
        en: "neko-auth hit an internal error and stopped. Your vault was not modified.\n\
             Re-run with RUST_BACKTRACE=1 for details (the output may contain secrets).",
        zh_hans: "neko-auth 遇到内部错误并已停止。你的保险库未被修改。\n\
                  需要细节请加 RUST_BACKTRACE=1 重跑（输出可能包含密钥）。",
        zh_hant: "neko-auth 遇到內部錯誤並已停止。你的保險庫未被修改。\n\
                  需要細節請加 RUST_BACKTRACE=1 重跑（輸出可能包含金鑰）。",
        ja: "neko-auth は内部エラーで停止しました。保管庫は変更されていません。\n\
             詳細が必要なら RUST_BACKTRACE=1 を付けて再実行してください (出力にシークレットを含む場合があります)。";

    // -- update ------------------------------------------------------------

    fn update_no_repo() =>
        en: "no update repository is configured.\n\
             Set one with `config update_repo <owner>/<repo>`, or build with \
             NEKO_AUTH_REPO=<owner>/<repo>.",
        zh_hans: "没有配置更新仓库。\n\
                  用 `config update_repo <owner>/<repo>` 设置，或在构建时指定 \
                  NEKO_AUTH_REPO=<owner>/<repo>。",
        zh_hant: "沒有設定更新倉庫。\n\
                  用 `config update_repo <owner>/<repo>` 設定，或在建置時指定 \
                  NEKO_AUTH_REPO=<owner>/<repo>。",
        ja: "更新用リポジトリが設定されていません。\n\
             `config update_repo <owner>/<repo>` で設定するか、ビルド時に \
             NEKO_AUTH_REPO=<owner>/<repo> を指定してください。";

    fn update_contacting(repo: &str) =>
        en: "contacting github.com for {repo}…",
        zh_hans: "正在连接 github.com 查询 {repo}…",
        zh_hant: "正在連線 github.com 查詢 {repo}…",
        ja: "{repo} を github.com に問い合わせています…";

    fn update_up_to_date(version: &str) =>
        en: "neko-auth {version} is up to date",
        zh_hans: "neko-auth {version} 已是最新版本",
        zh_hant: "neko-auth {version} 已是最新版本",
        ja: "neko-auth {version} は最新です";

    fn update_available() =>
        en: "update available:",
        zh_hans: "有新版本：",
        zh_hant: "有新版本：",
        ja: "更新があります:";

    fn update_run_to_install() =>
        en: "run `update` without --check to install it.",
        zh_hans: "去掉 --check 运行 `update` 即可安装。",
        zh_hant: "去掉 --check 執行 `update` 即可安裝。",
        ja: "--check なしで `update` を実行するとインストールします。";

    fn update_downloading() =>
        en: "downloading…",
        zh_hans: "正在下载…",
        zh_hant: "正在下載…",
        ja: "ダウンロード中…";

    fn update_verified() =>
        en: "signature and checksum verified",
        zh_hans: "签名与校验和已验证",
        zh_hant: "簽章與校驗和已驗證",
        ja: "署名とチェックサムを検証しました";

    fn update_done(version: &str) =>
        en: "updated to {version}",
        zh_hans: "已更新到 {version}",
        zh_hant: "已更新到 {version}",
        ja: "{version} に更新しました";

    fn update_vault_untouched() =>
        en: "your vault was not touched.",
        zh_hans: "你的保险库没有被改动。",
        zh_hant: "你的保險庫沒有被更動。",
        ja: "保管庫には触れていません。";

    fn update_no_signing_key() =>
        en: "this build has no release signing key compiled in, so a download cannot be \
             verified. Install the update manually from the release page above.",
        zh_hans: "这个构建没有编入发布签名公钥，因此无法验证下载内容。\
                  请从上面的发布页面手动安装。",
        zh_hant: "這個組建沒有編入發布簽章公鑰，因此無法驗證下載內容。\
                  請從上面的發布頁面手動安裝。",
        ja: "このビルドにはリリース署名鍵が組み込まれていないため、ダウンロードを検証できません。\
             上のリリースページから手動でインストールしてください。";

    fn update_signature_bad() =>
        en: "the release signature does not verify. Do not install this download: either the \
             release was not signed by the expected key, or it was altered in transit.",
        zh_hans: "发布签名验证失败。请不要安装这个下载：要么发布不是用预期的密钥签名的，\
                  要么它在传输过程中被篡改。",
        zh_hant: "發布簽章驗證失敗。請不要安裝這個下載：要麼發布不是用預期的金鑰簽章的，\
                  要麼它在傳輸過程中被竄改。",
        ja: "リリース署名を検証できませんでした。このダウンロードはインストールしないでください。\
             想定した鍵で署名されていないか、転送中に改変されています。";

    fn update_checksum_bad(asset: &str) =>
        en: "the downloaded {asset} does not match its published checksum",
        zh_hans: "下载的 {asset} 与公布的校验和不符",
        zh_hant: "下載的 {asset} 與公布的校驗和不符",
        ja: "ダウンロードした {asset} が公開されたチェックサムと一致しません";

    fn update_missing_asset(name: &str) =>
        en: "this release has no `{name}`; install it manually instead",
        zh_hans: "这个发布里没有 `{name}`；请改为手动安装",
        zh_hant: "這個發布裡沒有 `{name}`；請改為手動安裝",
        ja: "このリリースには `{name}` がありません。手動でインストールしてください";

    fn update_not_available() =>
        en: "this build was compiled without update support",
        zh_hans: "这个构建没有编译更新支持",
        zh_hant: "這個組建沒有編譯更新支援",
        ja: "このビルドは更新機能を含んでいません";
}

messages! {
    // -- errors from the OTP and crypto layers -----------------------------

    fn err_digits_range(minimum: u32, maximum: u32, got: u32) =>
        en: "digit count must be between {minimum} and {maximum}, got {got}",
        zh_hans: "位数必须在 {minimum} 到 {maximum} 之间，收到的是 {got}",
        zh_hant: "位數必須在 {minimum} 到 {maximum} 之間，收到的是 {got}",
        ja: "桁数は {minimum}〜{maximum} の範囲で指定してください (指定値: {got})";

    fn err_period_range(maximum: u32, got: u32) =>
        en: "period must be between 1 and {maximum} seconds, got {got}",
        zh_hans: "周期必须在 1 到 {maximum} 秒之间，收到的是 {got}",
        zh_hant: "週期必須在 1 到 {maximum} 秒之間，收到的是 {got}",
        ja: "周期は 1〜{maximum} 秒で指定してください (指定値: {got})";

    fn err_empty_secret() =>
        en: "the shared secret is empty",
        zh_hans: "密钥是空的",
        zh_hant: "金鑰是空的",
        ja: "共有シークレットが空です";

    fn err_not_otpauth() =>
        en: "not an otpauth:// URI",
        zh_hans: "不是 otpauth:// 链接",
        zh_hant: "不是 otpauth:// 連結",
        ja: "otpauth:// の URI ではありません";

    fn err_unknown_otp_type(value: &str) =>
        en: "unknown OTP type `{value}` (expected totp or hotp)",
        zh_hans: "未知的 OTP 类型 `{value}`（应为 totp 或 hotp）",
        zh_hant: "未知的 OTP 類型 `{value}`（應為 totp 或 hotp）",
        ja: "不明な OTP の種類 `{value}` (totp または hotp)";

    fn err_no_secret_param() =>
        en: "the URI has no secret= parameter",
        zh_hans: "链接里没有 secret= 参数",
        zh_hant: "連結裡沒有 secret= 參數",
        ja: "URI に secret= パラメーターがありません";

    fn err_bad_base32() =>
        en: "the secret is not valid Base32",
        zh_hans: "密钥不是有效的 Base32",
        zh_hant: "金鑰不是有效的 Base32",
        ja: "シークレットが有効な Base32 ではありません";

    fn err_param_not_number(param: &str, value: &str) =>
        en: "`{param}` is not a valid number: `{value}`",
        zh_hans: "`{param}` 不是有效的数字：`{value}`",
        zh_hant: "`{param}` 不是有效的數字：`{value}`",
        ja: "`{param}` が数値ではありません: `{value}`";

    fn err_hotp_needs_counter() =>
        en: "a hotp URI must carry a counter= parameter",
        zh_hans: "hotp 链接必须带 counter= 参数",
        zh_hant: "hotp 連結必須帶 counter= 參數",
        ja: "hotp の URI には counter= パラメーターが必要です";

    fn err_bad_encoding() =>
        en: "the URI is not valid UTF-8 after percent-decoding",
        zh_hans: "链接百分号解码后不是有效的 UTF-8",
        zh_hant: "連結百分號解碼後不是有效的 UTF-8",
        ja: "パーセントデコード後の URI が有効な UTF-8 ではありません";

    fn err_not_migration() =>
        en: "not an otpauth-migration:// URI",
        zh_hans: "不是 otpauth-migration:// 链接",
        zh_hant: "不是 otpauth-migration:// 連結",
        ja: "otpauth-migration:// の URI ではありません";

    fn err_no_data_param() =>
        en: "the URI has no data= parameter",
        zh_hans: "链接里没有 data= 参数",
        zh_hant: "連結裡沒有 data= 參數",
        ja: "URI に data= パラメーターがありません";

    fn err_bad_base64() =>
        en: "the data= parameter is not valid Base64",
        zh_hans: "data= 参数不是有效的 Base64",
        zh_hant: "data= 參數不是有效的 Base64",
        ja: "data= パラメーターが有効な Base64 ではありません";

    fn err_migration_malformed() =>
        en: "the payload is truncated or not a valid migration message",
        zh_hans: "载荷不完整，或不是有效的迁移数据",
        zh_hant: "酬載不完整，或不是有效的遷移資料",
        ja: "ペイロードが途中で切れているか、移行データとして不正です";

    fn err_md5(name: &str) =>
        en: "account `{name}` uses MD5, which no authenticator app supports",
        zh_hans: "账号 `{name}` 使用 MD5，没有任何验证器支持它",
        zh_hant: "帳號 `{name}` 使用 MD5，沒有任何驗證器支援它",
        ja: "アカウント `{name}` は MD5 を使用しており、対応する認証アプリはありません";

    fn err_account_empty_secret(name: &str) =>
        en: "account `{name}` has an empty secret",
        zh_hans: "账号 `{name}` 的密钥是空的",
        zh_hant: "帳號 `{name}` 的金鑰是空的",
        ja: "アカウント `{name}` のシークレットが空です";

    fn err_unknown_algorithm_code(code: u64, name: &str) =>
        en: "unknown algorithm code {code} for account `{name}`",
        zh_hans: "账号 `{name}` 的算法编码 {code} 未知",
        zh_hant: "帳號 `{name}` 的演算法編碼 {code} 未知",
        ja: "アカウント `{name}` のアルゴリズムコード {code} は不明です";

    fn err_unknown_digits_code(code: u64, name: &str) =>
        en: "unknown digit count code {code} for account `{name}`",
        zh_hans: "账号 `{name}` 的位数编码 {code} 未知",
        zh_hant: "帳號 `{name}` 的位數編碼 {code} 未知",
        ja: "アカウント `{name}` の桁数コード {code} は不明です";

    fn err_mixed_batches() =>
        en: "these QR codes are from different exports; re-export and scan one set",
        zh_hans: "这些二维码来自不同批次的导出；请重新导出并只扫描同一组",
        zh_hant: "這些 QR code 來自不同批次的匯出；請重新匯出並只掃描同一組",
        ja: "これらの QR コードは別々のエクスポートのものです。書き出し直して 1 組だけ読み取ってください";

    fn err_authentication() =>
        en: "authentication failed",
        zh_hans: "认证失败",
        zh_hant: "驗證失敗",
        ja: "認証に失敗しました";

    fn err_ciphertext_malformed() =>
        en: "ciphertext is truncated or malformed",
        zh_hans: "密文不完整或格式错误",
        zh_hant: "密文不完整或格式錯誤",
        ja: "暗号文が途中で切れているか不正です";

    fn err_unsupported_format(version: u8) =>
        en: "unsupported blob format version {version}",
        zh_hans: "不支持的数据格式版本 {version}",
        zh_hant: "不支援的資料格式版本 {version}",
        ja: "未対応のデータ形式バージョン {version}";

    fn err_too_large(bytes: usize) =>
        en: "value is too large to store ({bytes} bytes)",
        zh_hans: "内容过大，无法存储（{bytes} 字节）",
        zh_hant: "內容過大，無法儲存（{bytes} 位元組）",
        ja: "値が大きすぎて保存できません ({bytes} バイト)";

    fn err_kdf_failed() =>
        en: "key derivation failed",
        zh_hans: "密钥派生失败",
        zh_hant: "金鑰衍生失敗",
        ja: "鍵の導出に失敗しました";

    fn err_rng() =>
        en: "the system random number generator failed",
        zh_hans: "系统随机数生成器失败",
        zh_hant: "系統亂數產生器失敗",
        ja: "システムの乱数生成に失敗しました";

    fn err_kdf_m_cost() =>
        en: "m_cost exceeds the 2 GiB limit",
        zh_hans: "m_cost 超过 2 GiB 上限",
        zh_hant: "m_cost 超過 2 GiB 上限",
        ja: "m_cost が 2 GiB の上限を超えています";

    fn err_kdf_t_cost() =>
        en: "t_cost out of range",
        zh_hans: "t_cost 超出范围",
        zh_hant: "t_cost 超出範圍",
        ja: "t_cost が範囲外です";

    fn err_kdf_p_cost() =>
        en: "p_cost out of range",
        zh_hans: "p_cost 超出范围",
        zh_hant: "p_cost 超出範圍",
        ja: "p_cost が範囲外です";

    fn err_kdf_m_too_small() =>
        en: "m_cost is too small for p_cost",
        zh_hans: "相对于 p_cost，m_cost 太小",
        zh_hant: "相對於 p_cost，m_cost 太小",
        ja: "p_cost に対して m_cost が小さすぎます";

    fn err_kdf_rejected() =>
        en: "rejected by argon2",
        zh_hans: "被 argon2 拒绝",
        zh_hant: "被 argon2 拒絕",
        ja: "argon2 に拒否されました";

    fn err_record_truncated() =>
        en: "account record is truncated",
        zh_hans: "账号记录不完整",
        zh_hant: "帳號紀錄不完整",
        ja: "アカウントのレコードが途中で切れています";

    fn err_record_version(version: u8) =>
        en: "unsupported account record version {version}",
        zh_hans: "不支持的账号记录版本 {version}",
        zh_hant: "不支援的帳號紀錄版本 {version}",
        ja: "未対応のアカウントレコードのバージョン {version}";

    fn err_record_enum(field: &str) =>
        en: "account record has an invalid {field} code",
        zh_hans: "账号记录中的 {field} 编码无效",
        zh_hant: "帳號紀錄中的 {field} 編碼無效",
        ja: "アカウントレコードの {field} コードが不正です";

    fn err_record_utf8() =>
        en: "account record contains invalid UTF-8",
        zh_hans: "账号记录包含无效的 UTF-8",
        zh_hant: "帳號紀錄包含無效的 UTF-8",
        ja: "アカウントレコードに不正な UTF-8 が含まれています";

    fn err_field_algorithm() =>
        en: "algorithm",
        zh_hans: "算法",
        zh_hant: "演算法",
        ja: "アルゴリズム";

    fn err_field_otp_type() =>
        en: "otp type",
        zh_hans: "OTP 类型",
        zh_hant: "OTP 類型",
        ja: "OTP の種類";
}

// ---------------------------------------------------------------------------
// Counted phrases
// ---------------------------------------------------------------------------
//
// English inflects for number and the others do not, so these few phrases are
// written by hand rather than forced through the macro. Messages that mention
// a quantity take the finished phrase, which keeps "1 account" from ever being
// rendered as "1 account(s)".

use crate::i18n::{current, Language};

/// Generates the same explicit-language method plus global-reading wrapper
/// pair that `messages!` produces, for phrases whose logic the macro cannot
/// express.
macro_rules! hand_written {
    ($(
        $(#[$meta:meta])*
        fn $name:ident ( $lang:ident $(, $arg:ident : $ty:ty)* $(,)? ) $body:block
    )*) => {
        impl Language {
            $(
                $(#[$meta])*
                pub fn $name(self $(, $arg: $ty)*) -> String {
                    // The receiver's name comes from the call site so that the
                    // body can actually refer to it; a binding introduced by
                    // the macro would be invisible to those tokens.
                    let $lang = self;
                    $body
                }
            )*
        }
        $(
            $(#[$meta])*
            #[inline]
            pub fn $name($($arg: $ty),*) -> String {
                current().$name($($arg),*)
            }
        )*
    };
}

hand_written! {
    fn account_count(lang, count: usize) {
        match lang {
            Language::English if count == 1 => "1 account".to_string(),
            Language::English => format!("{count} accounts"),
            Language::SimplifiedChinese => format!("{count} 个账号"),
            Language::TraditionalChinese => format!("{count} 個帳號"),
            Language::Japanese => format!("{count} 件のアカウント"),
        }
    }

    fn secret_count(lang, count: usize) {
        match lang {
            Language::English if count == 1 => "1 shared secret".to_string(),
            Language::English => format!("{count} shared secrets"),
            Language::SimplifiedChinese => format!("{count} 个密钥"),
            Language::TraditionalChinese => format!("{count} 個金鑰"),
            Language::Japanese => format!("{count} 件の共有シークレット"),
        }
    }

    fn qr_code_count(lang, count: usize) {
        match lang {
            Language::English if count == 1 => "1 QR code".to_string(),
            Language::English => format!("{count} QR codes"),
            Language::SimplifiedChinese => format!("{count} 个二维码"),
            Language::TraditionalChinese => format!("{count} 個 QR code"),
            Language::Japanese => format!("{count} 個の QR コード"),
        }
    }

    fn file_count(lang, count: usize) {
        match lang {
            Language::English if count == 1 => "1 file".to_string(),
            Language::English => format!("{count} files"),
            Language::SimplifiedChinese => format!("{count} 个文件"),
            Language::TraditionalChinese => format!("{count} 個檔案"),
            Language::Japanese => format!("{count} 個のファイル"),
        }
    }

    /// "read 3 QR codes from 2 files"
    fn read_qr_codes(lang, codes: usize, files: usize) {
        let codes = lang.qr_code_count(codes);
        let files = lang.file_count(files);
        match lang {
            Language::English => format!("read {codes} from {files}"),
            Language::SimplifiedChinese => format!("从 {files}中读到 {codes}"),
            Language::TraditionalChinese => format!("從 {files}中讀到 {codes}"),
            Language::Japanese => format!("{files}から {codes}を読み取りました"),
        }
    }

    /// "added 3 accounts"
    fn added_accounts(lang, count: usize) {
        let accounts = lang.account_count(count);
        match lang {
            Language::English => format!("added {accounts}"),
            Language::SimplifiedChinese => format!("已添加 {accounts}"),
            Language::TraditionalChinese => format!("已新增 {accounts}"),
            Language::Japanese => format!("{accounts}を追加しました"),
        }
    }

    /// Which QR codes of a Google export have not been scanned yet.
    ///
    /// Hand-written because it joins a list with the language's own
    /// conjunction, which the message macro cannot express.
    fn incomplete_batch(lang, missing: &[i32], total: i32) {
        let numbers: Vec<String> = missing.iter().map(i32::to_string).collect();
        let list = match lang {
            Language::English => match numbers.as_slice() {
                [] => String::new(),
                [only] => only.clone(),
                [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
            },
            // Chinese and Japanese both enumerate with the ideographic comma.
            _ => numbers.join("、"),
        };

        match lang {
            Language::English if missing.len() == 1 => format!(
                "this Google export is split across {total} QR codes and one is still missing; \
                 scan part {list} too"
            ),
            Language::English => format!(
                "this Google export is split across {total} QR codes and some are still \
                 missing; scan parts {list} too"
            ),
            Language::SimplifiedChinese => format!(
                "这份谷歌导出共分成 {total} 张二维码，还差第 {list} 张；请把剩下的也一起扫描"
            ),
            Language::TraditionalChinese => format!(
                "這份 Google 匯出共分成 {total} 張 QR code，還差第 {list} 張；請把剩下的也一起掃描"
            ),
            Language::Japanese => format!(
                "この Google のエクスポートは QR コード {total} 枚に分かれており、{list} 枚目が\
                 まだ足りません。残りも読み取ってください"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_message_renders_in_every_language() {
        assert_eq!(Language::English.init_done(), "vault created");
        assert_eq!(Language::SimplifiedChinese.init_done(), "保险库已创建");
        assert_eq!(Language::TraditionalChinese.init_done(), "保險庫已建立");
        assert_eq!(Language::Japanese.init_done(), "保管庫を作成しました");
    }

    #[test]
    fn arguments_are_interpolated_in_every_language() {
        for language in Language::ALL {
            let rendered = language.deleted("GitHub (zoe)");
            assert!(
                rendered.contains("GitHub (zoe)"),
                "{language:?}: {rendered}"
            );
            assert!(
                !rendered.contains('{'),
                "{language:?} left a placeholder: {rendered}"
            );
        }
    }

    /// Traditional Chinese must not be a character-for-character conversion of
    /// the simplified text: the vocabulary differs, and using mainland terms is
    /// the most visible way to get this wrong for a reader in Taiwan.
    #[test]
    fn traditional_chinese_uses_taiwanese_vocabulary() {
        let cases: [(String, &str, &str); 4] = [
            (Language::TraditionalChinese.doctor_file(), "檔案", "文件"),
            (
                Language::TraditionalChinese.column_account(),
                "帳號",
                "账号",
            ),
            (Language::TraditionalChinese.cmd_config(), "設定", "设置"),
            (Language::TraditionalChinese.wal_warning(), "網路", "网络"),
        ];
        for (rendered, expected, mainland) in cases {
            assert!(
                rendered.contains(expected),
                "expected {expected} in {rendered}"
            );
            assert!(!rendered.contains(mainland), "mainland term in {rendered}");
        }
    }

    #[test]
    fn english_inflects_counts_but_the_others_do_not() {
        assert_eq!(Language::English.account_count(1), "1 account");
        assert_eq!(Language::English.account_count(4), "4 accounts");
        assert_eq!(Language::SimplifiedChinese.account_count(1), "1 个账号");
        assert_eq!(Language::SimplifiedChinese.account_count(4), "4 个账号");
        assert_eq!(Language::TraditionalChinese.account_count(4), "4 個帳號");
        assert_eq!(Language::Japanese.account_count(4), "4 件のアカウント");
    }

    #[test]
    fn the_missing_part_list_reads_naturally_in_each_language() {
        let en = Language::English;
        assert!(en
            .incomplete_batch(&[2], 3)
            .contains("one is still missing"));
        assert!(en.incomplete_batch(&[2], 3).contains("part 2"));
        assert!(en.incomplete_batch(&[2, 3], 3).contains("parts 2 and 3"));
        assert!(Language::SimplifiedChinese
            .incomplete_batch(&[2, 3], 3)
            .contains("第 2、3 张"));
        assert!(Language::Japanese
            .incomplete_batch(&[2, 3], 3)
            .contains("2、3 枚目"));
    }

    #[test]
    fn the_free_functions_read_the_active_language() {
        // The default is English, and nothing in the test suite changes it:
        // a test that switched the process-wide language could be observed by
        // another test asserting on an English message.
        assert_eq!(init_done(), Language::English.init_done());
    }
}

messages! {
    fn err_invalid_kdf_params(detail: &str) =>
        en: "invalid KDF parameters: {detail}",
        zh_hans: "KDF 参数无效：{detail}",
        zh_hant: "KDF 參數無效：{detail}",
        ja: "KDF パラメーターが不正です: {detail}";
}

messages! {
    // -- vault file diagnostics --------------------------------------------

    fn err_malformed_account_id(bytes: usize) =>
        en: "an account has a malformed id ({bytes} bytes)",
        zh_hans: "某个账号的 id 格式错误（{bytes} 字节）",
        zh_hant: "某個帳號的 id 格式錯誤（{bytes} 位元組）",
        ja: "アカウントの ID が不正です ({bytes} バイト)";

    fn err_account_name_utf8() =>
        en: "an account name is not valid UTF-8",
        zh_hans: "某个账号名不是有效的 UTF-8",
        zh_hant: "某個帳號名稱不是有效的 UTF-8",
        ja: "アカウント名が有効な UTF-8 ではありません";

    fn err_unexpected_db_object(kind: &str, name: &str) =>
        en: "the vault contains an unexpected database object ({kind} `{name}`). \
             This file was not written by neko-auth; refusing to use it.",
        zh_hans: "保险库里有非预期的数据库对象（{kind} `{name}`）。\
                  这个文件不是 neko-auth 写出的，拒绝使用。",
        zh_hant: "保險庫裡有非預期的資料庫物件（{kind} `{name}`）。\
                  這個檔案不是 neko-auth 寫出的，拒絕使用。",
        ja: "保管庫に想定外のデータベースオブジェクト ({kind} `{name}`) があります。\
             neko-auth が書き出したファイルではないため、使用を拒否します。";

    fn err_missing_db_object(name: &str, kind: &str) =>
        en: "the vault is missing its `{name}` {kind}; the file is damaged",
        zh_hans: "保险库缺少 `{name}` {kind}；文件已损坏",
        zh_hant: "保險庫缺少 `{name}` {kind}；檔案已損壞",
        ja: "保管庫に `{name}` {kind} がありません。ファイルが破損しています";

    fn err_header_unreadable() =>
        en: "the vault header is missing or unreadable",
        zh_hans: "保险库头部缺失或无法读取",
        zh_hant: "保險庫標頭缺失或無法讀取",
        ja: "保管庫のヘッダーが存在しないか読み取れません";

    fn err_format_version(found: u64, expected: u64) =>
        en: "this vault uses on-disk format {found}, but this build of neko-auth speaks \
             {expected}. Upgrade neko-auth to open it.",
        zh_hans: "这个保险库使用磁盘格式 {found}，而当前 neko-auth 只支持 {expected}。\
                  请升级 neko-auth 后再打开。",
        zh_hant: "這個保險庫使用磁碟格式 {found}，而目前 neko-auth 只支援 {expected}。\
                  請升級 neko-auth 後再開啟。",
        ja: "この保管庫のディスク形式は {found} ですが、この neko-auth は {expected} に\
             対応しています。neko-auth を更新してください。";

    fn err_schema_version(found: u64, expected: u64) =>
        en: "this vault uses schema version {found}, but this build speaks {expected}.",
        zh_hans: "这个保险库的 schema 版本是 {found}，而当前构建只支持 {expected}。",
        zh_hant: "這個保險庫的 schema 版本是 {found}，而目前組建只支援 {expected}。",
        ja: "この保管庫のスキーマバージョンは {found} ですが、このビルドは {expected} に対応しています。";

    fn err_unsupported_kdf(algorithm: &str) =>
        en: "unsupported key-derivation algorithm `{algorithm}`",
        zh_hans: "不支持的密钥派生算法 `{algorithm}`",
        zh_hant: "不支援的金鑰衍生演算法 `{algorithm}`",
        ja: "未対応の鍵導出アルゴリズム `{algorithm}`";

    fn err_header_kdf(detail: &str) =>
        en: "the vault header has invalid KDF parameters: {detail}",
        zh_hans: "保险库头部的 KDF 参数无效：{detail}",
        zh_hant: "保險庫標頭的 KDF 參數無效：{detail}",
        ja: "保管庫ヘッダーの KDF パラメーターが不正です: {detail}";

    fn err_header_salt(found: usize, expected: usize) =>
        en: "the vault header has a {found}-byte salt; expected {expected}",
        zh_hans: "保险库头部的盐是 {found} 字节，应为 {expected} 字节",
        zh_hant: "保險庫標頭的鹽是 {found} 位元組，應為 {expected} 位元組",
        ja: "保管庫ヘッダーのソルトが {found} バイトです。{expected} バイトである必要があります";

    fn err_header_out_of_range(value: i64) =>
        en: "the vault header contains an out-of-range value: {value}",
        zh_hans: "保险库头部包含超出范围的值：{value}",
        zh_hant: "保險庫標頭包含超出範圍的值：{value}",
        ja: "保管庫ヘッダーに範囲外の値があります: {value}";
}

messages! {
    // -- backup file diagnostics -------------------------------------------

    fn err_backup_format(path: &str, found: u64, expected: u64) =>
        en: "{path} uses backup format {found}, but this build reads {expected}",
        zh_hans: "{path} 的备份格式是 {found}，而当前构建只能读 {expected}",
        zh_hant: "{path} 的備份格式是 {found}，而目前組建只能讀 {expected}",
        ja: "{path} のバックアップ形式は {found} ですが、このビルドが読めるのは {expected} です";

    fn err_backup_kdf(path: &str) =>
        en: "{path} uses an unsupported key-derivation algorithm",
        zh_hans: "{path} 使用了不支持的密钥派生算法",
        zh_hant: "{path} 使用了不支援的金鑰衍生演算法",
        ja: "{path} は未対応の鍵導出アルゴリズムを使用しています";

    fn err_backup_params(path: &str, detail: &str) =>
        en: "{path} has invalid KDF parameters: {detail}",
        zh_hans: "{path} 的 KDF 参数无效：{detail}",
        zh_hant: "{path} 的 KDF 參數無效：{detail}",
        ja: "{path} の KDF パラメーターが不正です: {detail}";

    fn err_backup_unknown_algorithm() =>
        en: "the backup contains an unknown algorithm",
        zh_hans: "备份中包含未知的算法",
        zh_hant: "備份中包含未知的演算法",
        ja: "バックアップに不明なアルゴリズムが含まれています";

    fn err_backup_unknown_type() =>
        en: "the backup contains an unknown OTP type",
        zh_hans: "备份中包含未知的 OTP 类型",
        zh_hant: "備份中包含未知的 OTP 類型",
        ja: "バックアップに不明な OTP の種類が含まれています";

    fn err_backup_utf8() =>
        en: "the backup contains invalid UTF-8",
        zh_hans: "备份中包含无效的 UTF-8",
        zh_hant: "備份中包含無效的 UTF-8",
        ja: "バックアップに不正な UTF-8 が含まれています";

    fn err_cannot_read(path: &str) =>
        en: "cannot read {path}",
        zh_hans: "无法读取 {path}",
        zh_hant: "無法讀取 {path}",
        ja: "{path} を読み込めません";

    fn err_cannot_write(path: &str) =>
        en: "cannot write {path}",
        zh_hans: "无法写入 {path}",
        zh_hant: "無法寫入 {path}",
        ja: "{path} に書き込めません";
}

messages! {
    // -- command-line help -------------------------------------------------

    fn cli_about() =>
        en: "A fully offline TOTP authenticator with an encrypted vault",
        zh_hans: "完全离线的 TOTP 验证器，数据保存在加密的本地保险库中",
        zh_hant: "完全離線的 TOTP 驗證器，資料保存在加密的本機保險庫中",
        ja: "完全オフラインの TOTP 認証ツール。暗号化された保管庫にデータを保存します";

    fn cli_long_about() =>
        en: "neko-auth keeps two-factor secrets in a local, encrypted SQLite vault.\n\
             Nothing leaves the machine: the only command that touches the network is \
             `update`, and only when you run it.\n\n\
             Run with no arguments to open the interactive session.",
        zh_hans: "neko-auth 把双重验证的密钥保存在本地加密的 SQLite 保险库里。\n\
                  数据不会离开这台机器：唯一会联网的命令是 `update`，而且只在你主动运行时。\n\n\
                  不带参数运行即可进入交互式会话。",
        zh_hant: "neko-auth 把雙重驗證的金鑰保存在本機加密的 SQLite 保險庫裡。\n\
                  資料不會離開這台電腦：唯一會連網的指令是 `update`，而且只在你主動執行時。\n\n\
                  不帶參數執行即可進入互動式工作階段。",
        ja: "neko-auth は二要素認証のシークレットを、ローカルの暗号化された SQLite 保管庫に\
             保存します。\nデータがこのマシンを出ることはありません。ネットワークに接続する\
             コマンドは `update` だけで、しかも実行したときだけです。\n\n\
             引数なしで実行すると対話セッションを開きます。";

    fn cmd_init() =>
        en: "Create a new vault.",
        zh_hans: "创建一个新的保险库。",
        zh_hant: "建立一個新的保險庫。",
        ja: "新しい保管庫を作成します。";

    fn arg_vault() =>
        en: "Vault file to use (default: the per-user data directory).",
        zh_hans: "要使用的保险库文件（默认：当前用户的数据目录）。",
        zh_hant: "要使用的保險庫檔案（預設：目前使用者的資料目錄）。",
        ja: "使用する保管庫ファイル (既定: ユーザーごとのデータディレクトリ)。";

    fn arg_lang() =>
        en: "Interface language: auto, en, zh-Hans, zh-Hant, ja.",
        zh_hans: "界面语言：auto、en、zh-Hans、zh-Hant、ja。",
        zh_hant: "介面語言：auto、en、zh-Hans、zh-Hant、ja。",
        ja: "表示言語: auto、en、zh-Hans、zh-Hant、ja。";

    fn arg_kdf_profile() =>
        en: "Key-derivation cost: interactive, moderate, or paranoid.",
        zh_hans: "密钥派生开销：interactive、moderate 或 paranoid。",
        zh_hant: "金鑰衍生開銷：interactive、moderate 或 paranoid。",
        ja: "鍵導出コスト: interactive、moderate、paranoid。";

    fn arg_pattern() =>
        en: "Only show accounts matching this text.",
        zh_hans: "只显示匹配这段文字的账号。",
        zh_hant: "只顯示符合這段文字的帳號。",
        ja: "この文字列に一致するアカウントだけを表示します。";

    fn arg_name() =>
        en: "Any part of the issuer or account name.",
        zh_hans: "发行方或账号名的任意一部分。",
        zh_hant: "發行方或帳號名稱的任意一部分。",
        ja: "発行元またはアカウント名の一部。";

    fn arg_copy() =>
        en: "Also copy the code to the clipboard.",
        zh_hans: "同时把验证码复制到剪贴板。",
        zh_hant: "同時把驗證碼複製到剪貼簿。",
        ja: "コードをクリップボードにもコピーします。";

    fn arg_uri() =>
        en: "A single otpauth:// URI. Omit it to be prompted with the echo off.",
        zh_hans: "单条 otpauth:// 链接。省略则在不回显的提示下输入。",
        zh_hant: "單條 otpauth:// 連結。省略則在不回顯的提示下輸入。",
        ja: "otpauth:// の URI を 1 つ。省略すると非表示のプロンプトで入力します。";

    fn arg_qr_paths() =>
        en: "One or more images containing QR codes.",
        zh_hans: "一个或多个含二维码的图片文件。",
        zh_hant: "一個或多個含 QR code 的圖片檔案。",
        ja: "QR コードを含む画像ファイル (複数可)。";

    fn arg_import_file() =>
        en: "A text file of otpauth:// or otpauth-migration:// URIs, one per line.",
        zh_hans: "每行一条 otpauth:// 或 otpauth-migration:// 链接的文本文件。",
        zh_hant: "每行一條 otpauth:// 或 otpauth-migration:// 連結的文字檔案。",
        ja: "otpauth:// または otpauth-migration:// の URI を 1 行ずつ書いたテキストファイル。";

    fn arg_same_password() =>
        en: "Protect the backup with the current master password instead of a new one.",
        zh_hans: "用当前主密码保护备份，而不是设置新密码。",
        zh_hant: "用目前主密碼保護備份，而不是設定新密碼。",
        ja: "新しいパスワードではなく、現在のマスターパスワードでバックアップを保護します。";

    fn arg_config_key() =>
        en: "Setting to change. Omit to list everything.",
        zh_hans: "要修改的设置项。省略则列出全部。",
        zh_hant: "要修改的設定項。省略則列出全部。",
        ja: "変更する設定。省略するとすべて表示します。";

    fn arg_config_value() =>
        en: "New value. Omit to show just this setting.",
        zh_hans: "新的值。省略则只显示该设置项。",
        zh_hant: "新的值。省略則只顯示該設定項。",
        ja: "新しい値。省略するとその設定だけを表示します。";

    fn arg_check() =>
        en: "Only report whether a newer version exists.",
        zh_hans: "只报告是否有新版本。",
        zh_hant: "只回報是否有新版本。",
        ja: "新しいバージョンの有無だけを確認します。";

    fn sub_import_uri() =>
        en: "Import a single otpauth:// URI.",
        zh_hans: "导入单条 otpauth:// 链接。",
        zh_hant: "匯入單條 otpauth:// 連結。",
        ja: "otpauth:// の URI を 1 つ取り込みます。";

    fn sub_import_qr() =>
        en: "Import from images containing QR codes. A Google export split across several \
             codes must be given all at once.",
        zh_hans: "从含二维码的图片导入。谷歌验证器分成多张的导出必须一次性全部给出。",
        zh_hant: "從含 QR code 的圖片匯入。Google 驗證器分成多張的匯出必須一次性全部給出。",
        ja: "QR コードを含む画像から取り込みます。複数枚に分かれた Google のエクスポートは\
             一度にすべて指定してください。";

    fn sub_import_file() =>
        en: "Import from a text file of URIs.",
        zh_hans: "从一个 URI 文本文件导入。",
        zh_hant: "從一個 URI 文字檔案匯入。",
        ja: "URI を書いたテキストファイルから取り込みます。";

    fn sub_export_encrypted() =>
        en: "Write an encrypted .nekobak archive.",
        zh_hans: "写出加密的 .nekobak 备份文件。",
        zh_hant: "寫出加密的 .nekobak 備份檔案。",
        ja: "暗号化された .nekobak アーカイブを書き出します。";

    fn sub_export_plain() =>
        en: "Write unencrypted otpauth:// URIs. Requires a typed confirmation.",
        zh_hans: "写出未加密的 otpauth:// 链接。需要手动输入确认。",
        zh_hant: "寫出未加密的 otpauth:// 連結。需要手動輸入確認。",
        ja: "暗号化していない otpauth:// URI を書き出します。入力による確認が必要です。";
}

messages! {
    // -- help layout -------------------------------------------------------
    //
    // clap renders these section headings itself, in English; supplying a help
    // template is the only way to translate them. Its own parse errors stay in
    // English, which is a limit of the library rather than a choice.

    fn help_usage() =>
        en: "Usage:",
        zh_hans: "用法：",
        zh_hant: "用法：",
        ja: "使い方:";

    fn help_commands() =>
        en: "Commands:",
        zh_hans: "命令：",
        zh_hant: "指令：",
        ja: "コマンド:";

    fn help_options() =>
        en: "Options:",
        zh_hans: "选项：",
        zh_hant: "選項：",
        ja: "オプション:";
}

messages! {
    fn arg_help() =>
        en: "Print help",
        zh_hans: "显示帮助",
        zh_hant: "顯示說明",
        ja: "ヘルプを表示";

    fn arg_version() =>
        en: "Print version",
        zh_hans: "显示版本",
        zh_hant: "顯示版本",
        ja: "バージョンを表示";
}

messages! {
    fn help_arguments() =>
        en: "Arguments:",
        zh_hans: "参数：",
        zh_hant: "參數：",
        ja: "引数:";
}

messages! {
    fn update_no_checksum_entry(asset: &str) =>
        en: "SHA256SUMS has no entry for {asset}",
        zh_hans: "SHA256SUMS 里没有 {asset} 的条目",
        zh_hant: "SHA256SUMS 裡沒有 {asset} 的項目",
        ja: "SHA256SUMS に {asset} の項目がありません";

    fn update_archive_missing_binary(name: &str) =>
        en: "the release archive does not contain a `{name}`",
        zh_hans: "发布包里没有 `{name}`",
        zh_hant: "發布包裡沒有 `{name}`",
        ja: "リリースアーカイブに `{name}` が含まれていません";
}

messages! {
    // -- I/O and environment -----------------------------------------------

    fn err_config_invalid(path: &str) =>
        en: "{path} is not valid",
        zh_hans: "{path} 的内容无效",
        zh_hant: "{path} 的內容無效",
        ja: "{path} の内容が不正です";

    fn err_cannot_create_temp(dir: &str) =>
        en: "cannot create a temporary file in {dir}",
        zh_hans: "无法在 {dir} 中创建临时文件",
        zh_hant: "無法在 {dir} 中建立暫存檔案",
        ja: "{dir} に一時ファイルを作成できません";

    fn err_no_config_dir() =>
        en: "cannot determine the user configuration directory",
        zh_hans: "无法确定用户配置目录",
        zh_hant: "無法確定使用者設定目錄",
        ja: "ユーザー設定ディレクトリを特定できません";

    fn err_no_data_dir() =>
        en: "cannot determine the user data directory",
        zh_hans: "无法确定用户数据目录",
        zh_hant: "無法確定使用者資料目錄",
        ja: "ユーザーデータディレクトリを特定できません";

    fn err_cannot_create(path: &str) =>
        en: "cannot create {path}",
        zh_hans: "无法创建 {path}",
        zh_hant: "無法建立 {path}",
        ja: "{path} を作成できません";

    fn err_cannot_restrict(path: &str) =>
        en: "cannot restrict permissions on {path}",
        zh_hans: "无法收紧 {path} 的权限",
        zh_hant: "無法收緊 {path} 的權限",
        ja: "{path} の権限を制限できません";

    fn err_raw_mode() =>
        en: "cannot switch the terminal to raw mode",
        zh_hans: "无法把终端切换到 raw 模式",
        zh_hant: "無法把終端機切換到 raw 模式",
        ja: "端末を raw モードに切り替えられません";

    fn err_read_password_stdin() =>
        en: "cannot read the password from stdin",
        zh_hans: "无法从标准输入读取密码",
        zh_hant: "無法從標準輸入讀取密碼",
        ja: "標準入力からパスワードを読み取れません";

    // -- update transport --------------------------------------------------

    fn err_cannot_reach(url: &str) =>
        en: "cannot reach {url}",
        zh_hans: "无法访问 {url}",
        zh_hant: "無法存取 {url}",
        ja: "{url} に接続できません";

    fn err_cannot_download(url: &str) =>
        en: "cannot download {url}",
        zh_hans: "无法下载 {url}",
        zh_hant: "無法下載 {url}",
        ja: "{url} をダウンロードできません";

    fn err_github_bad_response() =>
        en: "GitHub returned something that is not a release description",
        zh_hans: "GitHub 返回的内容不是发布信息",
        zh_hant: "GitHub 回傳的內容不是發布資訊",
        ja: "GitHub の応答がリリース情報ではありません";

    fn err_cannot_replace_exe() =>
        en: "cannot replace the running executable",
        zh_hans: "无法替换正在运行的可执行文件",
        zh_hant: "無法替換正在執行的可執行檔",
        ja: "実行中の実行ファイルを置き換えられません";

    fn err_cannot_locate_exe() =>
        en: "cannot locate the running executable",
        zh_hans: "无法定位正在运行的可执行文件",
        zh_hant: "無法定位正在執行的可執行檔",
        ja: "実行中の実行ファイルの場所を特定できません";

    fn err_bad_own_version() =>
        en: "this build has a malformed version number",
        zh_hans: "这个构建的版本号格式错误",
        zh_hant: "這個組建的版本號格式錯誤",
        ja: "このビルドのバージョン番号が不正です";

    fn err_signature_file_bad() =>
        en: "the signature file is not readable as hex",
        zh_hans: "签名文件不是可读的十六进制",
        zh_hant: "簽章檔案不是可讀的十六進位",
        ja: "署名ファイルを 16 進数として読み取れません";

    fn err_checksums_not_text() =>
        en: "SHA256SUMS is not text",
        zh_hans: "SHA256SUMS 不是文本",
        zh_hant: "SHA256SUMS 不是文字",
        ja: "SHA256SUMS がテキストではありません";

    fn err_signing_key_malformed() =>
        en: "the signing key compiled into this build is malformed",
        zh_hans: "编入这个构建的签名公钥格式错误",
        zh_hant: "編入這個組建的簽章公鑰格式錯誤",
        ja: "このビルドに組み込まれた署名鍵が不正です";
}

messages! {
    fn err_cannot_open(path: &str) =>
        en: "cannot open {path}",
        zh_hans: "无法打开 {path}",
        zh_hant: "無法開啟 {path}",
        ja: "{path} を開けません";

    fn err_clipboard_unavailable() =>
        en: "cannot reach the system clipboard",
        zh_hans: "无法访问系统剪贴板",
        zh_hant: "無法存取系統剪貼簿",
        ja: "システムのクリップボードにアクセスできません";

    fn err_clipboard_write() =>
        en: "cannot write to the system clipboard",
        zh_hans: "无法写入系统剪贴板",
        zh_hant: "無法寫入系統剪貼簿",
        ja: "システムのクリップボードに書き込めません";
}

messages! {
    // -- identity ----------------------------------------------------------

    fn prompt_email() =>
        en: "Email: ",
        zh_hans: "邮箱：",
        zh_hant: "電子郵件：",
        ja: "メールアドレス: ";

    /// Used only under `hide_email`, where saying so avoids the impression
    /// that the terminal has stopped responding.
    fn prompt_email_hidden() =>
        en: "Email (hidden): ",
        zh_hans: "邮箱（不回显）：",
        zh_hant: "電子郵件（不回顯）：",
        ja: "メールアドレス (非表示): ";

    fn prompt_email_confirm() =>
        en: "Confirm email: ",
        zh_hans: "请再次输入邮箱：",
        zh_hant: "請再次輸入電子郵件：",
        ja: "メールアドレスをもう一度入力してください: ";

    fn email_is_empty() =>
        en: "the email cannot be empty",
        zh_hans: "邮箱不能为空",
        zh_hant: "電子郵件不能為空",
        ja: "メールアドレスは空にできません";

    fn email_mismatch() =>
        en: "the two email entries did not match",
        zh_hans: "两次输入的邮箱不一致",
        zh_hant: "兩次輸入的電子郵件不一致",
        ja: "入力したメールアドレスが一致しません";

    /// Deliberately says neither which half was wrong nor what was typed.
    fn unlock_failed_pair() =>
        en: "could not unlock: wrong email or password, or the vault is damaged",
        zh_hans: "无法解锁：邮箱或密码错误，或保险库已损坏",
        zh_hant: "無法解鎖：電子郵件或密碼錯誤，或保險庫已損壞",
        ja: "ロックを解除できません: メールアドレスかパスワードが違うか、保管庫が破損しています";

    fn init_email_note() =>
        en: "Your email is the second half of the key. It is not stored anywhere, so \
             anyone who copies this vault file has to guess both it and the password.",
        zh_hans: "邮箱是密钥的另一半。它不会被保存在任何地方 —— 拿到这个保险库文件的人，\
                  必须把邮箱和密码同时猜对。",
        zh_hant: "電子郵件是金鑰的另一半。它不會被保存在任何地方 —— 拿到這個保險庫檔案的人，\
                  必須把電子郵件和密碼同時猜對。",
        ja: "メールアドレスは鍵のもう半分です。どこにも保存されないため、この保管庫ファイルを\
             コピーした相手は、メールアドレスとパスワードの両方を当てる必要があります。";

    fn init_email_warning() =>
        en: "Because it is not stored, a mistyped email is indistinguishable from a wrong \
             password, and forgetting which address you used loses the vault just as \
             surely as forgetting the password.",
        zh_hans: "也正因为不保存，邮箱打错和密码输错是同一个报错，无法区分；\
                  忘了当初用的是哪个邮箱，跟忘记密码一样，保险库就永久打不开了。",
        zh_hant: "也正因為不保存，電子郵件打錯和密碼輸錯是同一個錯誤，無法區分；\
                  忘了當初用的是哪個信箱，跟忘記密碼一樣，保險庫就永久打不開了。",
        ja: "保存しないため、メールアドレスの打ち間違いはパスワード誤りと区別がつきません。\
             どのアドレスを使ったか忘れると、パスワードを忘れたときと同じく保管庫は開けません。";

    fn prompt_current_credentials() =>
        en: "Current email and password",
        zh_hans: "当前的邮箱与密码",
        zh_hant: "目前的電子郵件與密碼",
        ja: "現在のメールアドレスとパスワード";

    fn prompt_new_credentials() =>
        en: "New email and password",
        zh_hans: "新的邮箱与密码",
        zh_hant: "新的電子郵件與密碼",
        ja: "新しいメールアドレスとパスワード";

    fn credentials_changed() =>
        en: "email and master password changed",
        zh_hans: "邮箱与主密码已更改",
        zh_hant: "電子郵件與主密碼已變更",
        ja: "メールアドレスとマスターパスワードを変更しました";

    fn err_vault_v1(path: &str) =>
        en: "{path} was created by an older neko-auth that used a password alone. \
             This build requires an email as well, and cannot convert the file. \
             Export from the older version, then import here.",
        zh_hans: "{path} 是由只用密码的旧版 neko-auth 创建的。当前版本还需要邮箱，\
                  且无法直接转换该文件。请先用旧版导出，再在这里导入。",
        zh_hant: "{path} 是由只用密碼的舊版 neko-auth 建立的。目前版本還需要電子郵件，\
                  且無法直接轉換該檔案。請先用舊版匯出，再在這裡匯入。",
        ja: "{path} はパスワードのみを使う旧バージョンの neko-auth で作成されました。\
             このビルドはメールアドレスも必要で、ファイルを変換できません。\
             旧バージョンでエクスポートしてから、ここでインポートしてください。";
}

#[cfg(test)]
mod emphasis_tests {
    use crate::i18n::Language;

    /// The emphasised word is applied with `replacen`, which silently does
    /// nothing when the word is absent — the sentence would then print with no
    /// emphasis at all, in that language only.
    #[test]
    fn the_emphasised_word_occurs_in_its_sentence() {
        for language in Language::ALL {
            let word = language.init_only_word();
            let sentence = language.init_only_protection();
            assert!(
                sentence.contains(&word),
                "{language:?}: `{word}` is not in `{sentence}`"
            );
        }
    }
}

messages! {
    fn err_release_tag_not_a_version(tag: &str) =>
        en: "the latest release is tagged `{tag}`, which is not a version",
        zh_hans: "最新发布的标签是 `{tag}`，不是一个版本号",
        zh_hant: "最新發布的標籤是 `{tag}`，不是一個版本號",
        ja: "最新リリースのタグは `{tag}` で、バージョン番号ではありません";

    fn err_signature_wrong_length() =>
        en: "the signature is not 64 bytes",
        zh_hans: "签名不是 64 字节",
        zh_hant: "簽章不是 64 位元組",
        ja: "署名が 64 バイトではありません";
}

messages! {
    fn field_email() =>
        en: "email:",
        zh_hans: "邮箱：",
        zh_hant: "電子郵件：",
        ja: "メールアドレス:";

    fn init_remember_email() =>
        en: "Write that address down with your backup. It is not stored in the vault, and \
             unlocking needs it exactly as shown.",
        zh_hans: "把这个邮箱和备份记在一起。它不会保存在保险库里，解锁时需要和上面一字不差。",
        zh_hant: "把這個電子郵件和備份記在一起。它不會保存在保險庫裡，解鎖時需要和上面一字不差。",
        ja: "このアドレスはバックアップと一緒に控えておいてください。保管庫には保存されず、\
             ロック解除には表示どおりの入力が必要です。";
}

#[cfg(test)]
mod spacing_tests {
    use crate::i18n::Language;

    fn is_cjk(c: char) -> bool {
        matches!(c as u32,
            0x3040..=0x30FF | 0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF)
    }

    /// A counted phrase like "1 个文件" is substituted into a sentence, and the
    /// spacing has to be right on both sides of it. Chinese and Japanese put a
    /// space between a digit and adjacent script — `从1 个文件` reads as a typo
    /// — but never between two ideographs, so `文件 中读到` is equally wrong.
    /// Neither mistake is visible until a number is actually rendered.
    #[test]
    fn counted_phrases_are_spaced_inside_cjk_sentences() {
        for language in [
            Language::SimplifiedChinese,
            Language::TraditionalChinese,
            Language::Japanese,
        ] {
            for rendered in [
                language.read_qr_codes(1, 1),
                language.added_accounts(3),
                language.wrote_to(&language.account_count(2), "/tmp/x"),
                language.accounts_in_file(&language.account_count(2), "/tmp/x"),
                language.accounts_failed_to_decrypt(&language.account_count(1)),
            ] {
                let digits: Vec<usize> = rendered
                    .char_indices()
                    .filter(|(_, c)| c.is_ascii_digit())
                    .map(|(i, _)| i)
                    .collect();
                for index in digits {
                    if index == 0 {
                        continue;
                    }
                    let before = rendered[..index].chars().next_back().unwrap();
                    assert!(
                        before.is_ascii() || before.is_whitespace(),
                        "{language:?}: `{rendered}` runs a digit straight into `{before}`"
                    );
                }

                let chars: Vec<char> = rendered.chars().collect();
                for window in chars.windows(3) {
                    assert!(
                        !(is_cjk(window[0]) && window[1] == ' ' && is_cjk(window[2])),
                        "{language:?}: `{rendered}` has a space between two ideographs"
                    );
                }
            }
        }
    }
}

messages! {
    fn refreshes_in(seconds: u32) =>
        en: "refreshes in {seconds}s",
        zh_hans: "{seconds} 秒后刷新",
        zh_hant: "{seconds} 秒後更新",
        ja: "{seconds} 秒後に更新";

    fn some_codes_unreadable() =>
        en: "some codes could not be generated; run `doctor` to see which accounts are damaged",
        zh_hans: "有验证码无法生成；运行 `doctor` 查看是哪些账号损坏了",
        zh_hant: "有驗證碼無法產生；執行 `doctor` 查看是哪些帳號損壞了",
        ja: "一部のコードを生成できませんでした。`doctor` で破損したアカウントを確認してください";
}
