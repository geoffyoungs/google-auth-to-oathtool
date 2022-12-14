import Head from 'next/head'
import styles from '../styles/Home.module.css'
import { useRef, useState, useEffect } from 'react';
import parser from '../lib/otp.js';

export default function Home() {
  const inputEl = useRef(null);
  const videoRef = useRef(null);
  const menuRef = useRef(null);
  const [qr, setQR] = useState(false);
  const [deviceID, setDeviceID] = useState(null);
  const [devices, setDevices] = useState([]);
  const [list, setList] = useState([]);
  const [scan, setScan] = useState(false);

  const parseURL = () => {
    const url = inputEl.current.value;
    console.log(url);
    try {
      const list = parser(url);
      setList(list);
    } catch (e) {
      setList([])
      // error
    }
  };

  useEffect(() => {
    if (devices.length == 0) {
      navigator.mediaDevices.enumerateDevices().then(list => setDevices(list))
    }
    const bc = ('BarcodeDetector' in window);
    if (bc !== qr) setQR(bc);
    if (!bc) return;
    if (!scan && videoRef.current) {
      if (videoRef.current.srcObject)
      videoRef.current.srcObject.getTracks().forEach(track => track.stop());
      videoRef.current.srcObject = null;
    }
  });

  const stop = () => {
    if (videoRef.current && videoRef.current.srcObject) {
      videoRef.current.srcObject.getTracks().forEach(track => track.stop());
      videoRef.current.srcObject = null;
    }
    setScan(false)
  };


  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;
      // Check if device has camera
      if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
        // Use video without audio
        const constraints = {
          video: { width: 1280, height: 720 },
          audio: false
        }
        if (deviceID)
          constraints.video.deviceId = deviceID;

        console.log('setup webcam stream')
        // Start video stream
        navigator.mediaDevices.getUserMedia(constraints).then(stream => videoRef.current.srcObject = stream).catch((err) => {
          console.error(err);
        });
      }
    const barcodeDetector = new BarcodeDetector({ formats: ['qr_code'] });
    let iv;
      const detectCode = () => {
        // Start detecting codes on to the video element
        barcodeDetector.detect(videoRef.current).then(codes => {
          // If no codes exit function
          if (codes.length === 0) return;

          for (const barcode of codes)  {
            // Log the barcode to the console
            if (barcode.rawValue) {
              inputEl.current.value = barcode.rawValue;
              clearInterval(iv);
              videoRef.current.pause();

              setTimeout(() => {
                setScan(false);
                parseURL();
                if (videoRef.current && videoRef.current.srcObject)
                   videoRef.current.srcObject.getTracks().forEach(track => track.stop());
              }, 2000)
            }
          }
        }).catch(err => {
          // Log an error if one happens
          console.error(err);
        })
      }
      iv = setInterval(detectCode, 300);
      return (() => {
        clearInterval(iv);
        if (videoRef.current && videoRef.current.srcObject)
          videoRef.current.srcObject.getTracks().forEach(track => track.stop());
      })
  }), [videoRef, deviceID];

  const updateDeviceID = () => {
    setDeviceID(menuRef.current.value);
  };

  const menu = <div className={styles.fullscreen}>
    <button className={styles.close} onClick={stop}>&times;</button>
    <select className={styles.fullscreen_select} ref={menuRef} onChange={updateDeviceID} selected={deviceID}>{devices.map((dev, index) => <option key={index} value={dev.deviceId}>{dev.label}</option>)}</select>
    <video ref={videoRef} id="video" width="1280" height="720" controls={false} autoPlay></video>
  </div>;


  return (
    <div className={styles.container}>
      <Head>
        <title>Decode otpauth-migration URLs for use with oathtool / openconnect</title>
        <meta name="description" content="Generated by create next app" />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <main className={styles.main}>
        <h1 className={styles.title}>
        Decode otpauth-migration URLs for use with oathtool / openconnect
        </h1>

        {qr && scan ? menu : <></>}

        <div className={styles.description}>
          <textarea ref={inputEl} type="text" placeholder="Paste otpauth-migration:// URL here..."
            className={styles.largeinput} onChange={parseURL} name="oauth-migration-url" />
          <div>
          <button className={styles.button} onClick={parseURL}>Update</button>
          {qr ? <button className={styles.button} onClick={() => setScan(true)}>Scan QR</button> : <></>}
          </div>
        </div>

        <div className={styles.grid}>
          {list.map((el, index) => <div key={index}>
            <h3>{el.name} ({el.issuer})</h3>
            {el.type == 'totp' ?
              <div className={styles.code}>
                <span className={styles.prompt}>$</span> <code>oathtool -b --totp={el.algorithm} -d {el.digits} {el.secret}</code><br/>
                <span className={styles.prompt}>$</span> <code>sudo openconnect --user=$USER --token-mode=totp --token-secret={el.algorithm}:base32:{el.secret} $URL</code>
              </div>
              :
              <></>
            }

          </div>)}
        </div>
      </main>

      <footer className={styles.footer}>
        This site does not require network access or local storage.  It is recommended that you disable network access before using this page.
      </footer>
    </div>
  )
}
