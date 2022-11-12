"use strict";
let cont   = {doc:'', sig:''},
    flag   = {doc:false, sig:false},
    pubkey = '',
    mess   = '';

// Чтение файлов документа (как бинарного),
// ключа и подписи (как текстовых)
const readDoc = contKey => {
    let reader = new FileReader();
    reader.onload  = async e => {
        cont[contKey] = contKey == "sig" ?
                        e.target.result :
                        new Uint8Array(e.target.result);
        flag[contKey] = true;
        pubkey = await (await fetch("public.key")).text();   
        if (flag["doc"] && flag["sig"])
            document.querySelector("button").disabled = false;
    }
    reader.onerror = err => alert("Ошибка чтения файла");

    let fileObj = document.querySelector(`#${contKey}`).files[0];
    if (contKey == "sig") reader.readAsText(fileObj);
    else                  reader.readAsArrayBuffer(fileObj);
}

// Верификация подписи
const check = async () => {
    let readableStream = new ReadableStream({
        start(controller) {
            controller.enqueue(cont["doc"]);
            controller.close();
        }
    });

    let message = await openpgp.createMessage({ binary: readableStream });


    let signature = await openpgp.readSignature({
        armoredSignature: cont["sig"] // parse detached signature
    });

    const publicKey = await openpgp.readKey({ armoredKey: pubkey });

    const verificationResult = await openpgp.verify({
        message:    message,
        signature:  signature,
        verificationKeys: publicKey
    });
    for await (const chunk of verificationResult.data) {}
    try {
        await verificationResult.signatures[0].verified; // throws on invalid signature
        document.querySelector("output").innerHTML = `Підпис є дійсним. Ідентифікатор підпису: ${verificationResult.signatures[0].keyID.toHex()}`;
     } catch (e) {
        document.querySelector("output").innerHTML = `Підпис НЕ Є дійсним. Помилка перевірки типу: ${e.message}`;
        throw new Error('Signature could not be verified: ' + e.message);
    }
    //const {valid} = verified.signatures[0];
    //mess = "Электронная подпись НЕ является подлинной!";
    //if (valid) mess = "Электронная подпись является подлинной.";
    //document.querySelector("output").innerHTML = mess;
}