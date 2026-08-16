import { useEffect } from "react";

const PageMeta = ({
  title,
  description,
}: {
  title: string;
  description: string;
}) => {
  useEffect(() => {
    document.title = `${title} · GuardianOS-AI`;
  }, [title]);
  useEffect(() => {
    const meta = document.querySelector("meta[name='description']");
    if (meta) {
      meta.setAttribute("content", description);
    }
  }, [description]);
  return null;
};

export default PageMeta;
