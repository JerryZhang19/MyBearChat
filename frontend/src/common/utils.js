import { decode } from 'jsonwebtoken';
import Cookies from 'universal-cookie';

const cookies = new Cookies();

export function getUUID() {
  let loginToken = cookies.get("access_token");
  return getUUIDFromToken(loginToken);
}

function getUUIDFromToken(token) {
  // TODO: verify signature; return error if invalid
  // TODO: verify header and payload; return error if invalid
  let decoded = decode(token, {complete: true});
  if (decoded === null) {
    return null;
  }
  return decoded.payload.UserID;
}

export function request(method, url, qs, body) {
  return new Promise((resolve, reject) => {
    let xhr = new XMLHttpRequest();
    let u = new URL(url);
    for (const [key, value] of Object.entries(qs)) {
      u.searchParams.append(key, value);
    }
    xhr.open(method, u.toString(), true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.withCredentials = true;
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(xhr);
      } else {
        reject(xhr);
      }
    };
    xhr.onerror = () => {
      reject(xhr.status);
    };
    xhr.send(body);
  });
}

export const HOST = "<EC2 IP>";

