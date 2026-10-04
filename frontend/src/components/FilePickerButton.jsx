import { useRef } from 'react'

// FilePickerButton: a normal-looking button that opens the file chooser
// and hands the chosen file to `onFile`.
export default function FilePickerButton({ onFile, accept, className, disabled, children }) {
  const inputRef = useRef(null)
  return (
    <>
      <button type="button" onClick={() => inputRef.current.click()} className={className} disabled={disabled}>
        {children}
      </button>
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        className="hidden"
        tabIndex={-1}
        onChange={(e) => {
          const file = e.target.files[0]
          e.target.value = '' // allow picking the same file again
          if (file) onFile(file)
        }}
      />
    </>
  )
}
