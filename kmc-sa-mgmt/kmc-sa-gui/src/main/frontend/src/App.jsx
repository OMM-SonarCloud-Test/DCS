import {Fragment, useEffect, useState} from 'react'
import './App.css'
import {useLocalStorageBool} from "./sa/useLocalStorage.js";
import {
    AppBar,
    Box,
    Container,
    createTheme,
    CssBaseline, IconButton,
    ThemeProvider,
    Toolbar,
    Tooltip,
    Typography
} from "@mui/material";
import '@fontsource/roboto/300.css'
import '@fontsource/roboto/400.css'
import '@fontsource/roboto/500.css'
import '@fontsource/roboto/700.css'
import '@fontsource/roboto-mono/300.css'
import '@fontsource/roboto-mono/400.css'
import '@fontsource/roboto-mono/500.css'
import '@fontsource/roboto-mono/700.css'
import {Brightness3, Brightness7, Circle} from "@mui/icons-material";
import {SnackbarProvider} from "notistack";
import ErrorBoundary from "./sa/ErrorBoundary.jsx";
import {status} from "./sa/api";
import BasicTabs from "./sa/SaTabs.jsx";

function App() {
    const dark = {
        palette: {
            mode: 'dark',
        },
    }

    const light = {
        palette: {
            mode: 'light'
        }
    }

    const [theme, setTheme] = useLocalStorageBool("theme", true)
    const icon = !theme ? <Brightness3/> : <Brightness7/>
    const appliedTheme = createTheme(theme ? dark : light)
    const [dbStatus, setDbStatus] = useState("error")

    const checkStatus = () => status((r) => {
        setDbStatus("success")
    }, (e) => {
        setDbStatus("error")
    })

    useEffect(() => {
        checkStatus()
        const interval = setInterval(() => {
            checkStatus()
        }, 5000)
        return () => clearInterval(interval)
    }, [])

    return (<Fragment>
        <ThemeProvider theme={appliedTheme}>
            <SnackbarProvider maxSnack={5}>
                <CssBaseline/>
                <AppBar position={"static"}>
                    <Container maxWidth={"xl"}>
                        <Toolbar disableGutters>
                            <Typography variant={"h6"} sx={{flexGrow: 1}} noWrap>AMMOS Security Association Database
                                (SADB) Management</Typography>
                            <Box sx={{flexGrow: 0}}>
                                <Tooltip title={'Database is ' + (dbStatus === "success" ? "up" : "down")}><span><Circle
                                    color={dbStatus} sx={{"verticalAlign": "middle"}}/></span></Tooltip>
                                <Tooltip title={'Switch to ' + (theme ? 'light' : 'dark') + ' theme'}><IconButton
                                    onClick={() => setTheme(!theme)}>{icon}</IconButton></Tooltip>
                            </Box>
                        </Toolbar>
                    </Container>
                </AppBar>
                <div className="App">
                    <Container maxWidth={"xl"}>
                        <Box sx={{
                            marginY: 2,
                        }}>
                            <ErrorBoundary>
                                <BasicTabs/>
                                {/*<SaTable/>*/}
                            </ErrorBoundary>
                        </Box>
                    </Container>
                </div>
            </SnackbarProvider>
        </ThemeProvider>
    </Fragment>);
}

export default App
