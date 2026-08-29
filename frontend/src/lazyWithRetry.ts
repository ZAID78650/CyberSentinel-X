import { lazy } from "react";

/**
 * Retry wrapper for React.lazy() imports.
 * When a new deploy changes chunk hashes, the browser may still reference
 * old cached chunks. This retries the dynamic import up to `retries` times
 * before giving up.
 */
export function lazyWithRetry<T extends React.ComponentType<any>>(
  importFn: () => Promise<{ default: T }>,
  retries = 2,
): React.LazyExoticComponent<T> {
  return lazy(() => {
    return new Promise<{ default: T }>((resolve, reject) => {
      const attempt = (remaining: number) => {
        importFn()
          .then(resolve)
          .catch((err) => {
            if (remaining > 0) {
              setTimeout(() => attempt(remaining - 1), 100);
            } else {
              reject(err);
            }
          });
      };
      attempt(retries);
    });
  });
}
