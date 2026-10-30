import { useEffect, useRef, useState } from "react";

/**
 * Browser-only webcam control (navigator.mediaDevices.getUserMedia) for the
 * existing camera device card. Deliberately NOT wired into MQTT or any
 * backend — nothing is transmitted, recorded, or sent anywhere; the stream
 * only exists inside this browser tab and stops the moment turnOff() runs
 * or the component unmounts.
 */
export function useWebcam() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const [active, setActive] = useState(false);
  const [error, setError] = useState("");

  async function turnOn() {
    setError("");
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false });
      streamRef.current = stream;
      // Don't touch videoRef.current here: the <video> element only exists
      // in the DOM once `active` is true and React has re-rendered, so at
      // this point the ref is still null. Attaching the stream has to wait
      // for that render to actually happen — see the effect below.
      setActive(true);
    } catch {
      setError("Couldn't access your webcam. Check the browser's camera permission for this page, and that no other app is using it.");
    }
  }

  function turnOff() {
    streamRef.current?.getTracks().forEach((track) => track.stop());
    streamRef.current = null;
    setActive(false);
  }

  // Runs after React has mounted the <video> element (which only happens
  // once `active` flips true), so videoRef.current is guaranteed to exist
  // here even though it didn't yet inside turnOn().
  useEffect(() => {
    if (active && videoRef.current && streamRef.current) {
      videoRef.current.srcObject = streamRef.current;
    }
  }, [active]);

  // Release the camera on unmount too, not just on an explicit turnOff().
  useEffect(() => () => turnOff(), []);

  return { videoRef, active, error, turnOn, turnOff };
}
