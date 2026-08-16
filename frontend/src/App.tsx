import { BrowserRouter as Router, Routes, Route } from "react-router";
import AppLayout from "./layout/AppLayout";
import { ScrollToTop } from "./components/common/ScrollToTop";
import Overview from "./pages/Overview";
import Threats from "./pages/Threats";
import KernelActivity from "./pages/KernelActivity";
import Processes from "./pages/Processes";
import AIAnalysis from "./pages/AIAnalysis";
import Response from "./pages/Response";
import SystemHealth from "./pages/SystemHealth";
import Settings from "./pages/Settings";
import NotFound from "./pages/NotFound";

export default function App() {
  return (
    <Router>
      <ScrollToTop />
      <Routes>
        <Route element={<AppLayout />}>
          <Route index path="/" element={<Overview />} />
          <Route path="/threats" element={<Threats />} />
          <Route path="/threats/:reportId" element={<Threats />} />
          <Route path="/kernel" element={<KernelActivity />} />
          <Route path="/processes" element={<Processes />} />
          <Route path="/analysis" element={<AIAnalysis />} />
          <Route path="/response" element={<Response />} />
          <Route path="/health" element={<SystemHealth />} />
          <Route path="/settings" element={<Settings />} />
        </Route>
        <Route path="*" element={<NotFound />} />
      </Routes>
    </Router>
  );
}
